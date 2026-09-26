//! Persistent browser WebSocket for Kaspa wRPC notifications.
//!
//! Request/response traffic uses request-scoped sockets; subscriptions need a
//! socket that stays open. Browser objects are not `Send`, so sockets live in a
//! thread-local registry and callers hold only an opaque key.
#![cfg(target_arch = "wasm32")]

use std::{
    cell::{Cell, RefCell},
    collections::{HashMap, VecDeque},
    rc::Rc,
};

use wasm_bindgen::{closure::Closure, JsCast};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Event, MessageEvent, WebSocket};

use crate::network::{
    error::NetworkError,
    wrpc::{
        operation::Operation,
        request::{self, WrpcRequest},
    },
};

type Waiter = js_sys::Function;

struct Socket {
    websocket: WebSocket,
    frames: RefCell<VecDeque<Vec<u8>>>,
    waiter: RefCell<Option<Waiter>>,
    closed: Cell<bool>,
    next_request_id: Cell<u64>,
    _handlers: RefCell<Vec<Handler>>,
}

type JsValueEvent = wasm_bindgen::JsValue;
type Handler = Closure<dyn FnMut(JsValueEvent)>;

thread_local! {
    static SOCKETS: RefCell<HashMap<u64, Rc<Socket>>> = RefCell::new(HashMap::new());
    static NEXT_KEY: Cell<u64> = const { Cell::new(1) };
}

fn socket(key: u64) -> Result<Rc<Socket>, NetworkError> {
    SOCKETS
        .with(|sockets| sockets.borrow().get(&key).cloned())
        .ok_or_else(|| NetworkError::ConnectionFailed("notification socket is closed".into()))
}

/// Open a persistent notification socket to `endpoint` and return its key.
pub async fn open(endpoint: &str) -> Result<u64, NetworkError> {
    let websocket = WebSocket::new(endpoint)
        .map_err(|error| NetworkError::ConnectionFailed(format!("{error:?}")))?;
    websocket.set_binary_type(web_sys::BinaryType::Arraybuffer);
    let socket = Rc::new(Socket {
        websocket: websocket.clone(),
        frames: RefCell::new(VecDeque::new()),
        waiter: RefCell::new(None),
        closed: Cell::new(false),
        next_request_id: Cell::new(1),
        _handlers: RefCell::new(Vec::new()),
    });
    wait_open(&websocket).await?;
    install_handlers(&socket);
    let key = NEXT_KEY.with(|next| {
        let key = next.get();
        next.set(key.wrapping_add(1));
        key
    });
    SOCKETS.with(|sockets| sockets.borrow_mut().insert(key, socket));
    Ok(key)
}

fn install_handlers(socket: &Rc<Socket>) {
    let on_message = {
        let socket = Rc::downgrade(socket);
        Closure::<dyn FnMut(JsValueEvent)>::new(move |event: JsValueEvent| {
            let Some(socket) = socket.upgrade() else {
                return;
            };
            let Ok(event) = event.dyn_into::<MessageEvent>() else {
                return;
            };
            if let Ok(buffer) = event.data().dyn_into::<js_sys::ArrayBuffer>() {
                socket
                    .frames
                    .borrow_mut()
                    .push_back(js_sys::Uint8Array::new(&buffer).to_vec());
                wake(&socket);
            }
        })
    };
    let on_close = {
        let socket = Rc::downgrade(socket);
        Closure::<dyn FnMut(JsValueEvent)>::new(move |_event: JsValueEvent| {
            if let Some(socket) = socket.upgrade() {
                socket.closed.set(true);
                wake(&socket);
            }
        })
    };
    socket
        .websocket
        .set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    socket
        .websocket
        .set_onclose(Some(on_close.as_ref().unchecked_ref()));
    socket
        .websocket
        .set_onerror(Some(on_close.as_ref().unchecked_ref()));
    socket._handlers.borrow_mut().extend([on_message, on_close]);
}

fn wake(socket: &Socket) {
    if let Some(resolve) = socket.waiter.borrow_mut().take() {
        let _ = resolve.call0(&wasm_bindgen::JsValue::NULL);
    }
}

/// Resolve once the socket opens, errors, or closes; true only when open.
async fn wait_open(websocket: &WebSocket) -> Result<(), NetworkError> {
    let opened = Rc::new(Cell::new(false));
    let promise = js_sys::Promise::new(&mut |resolve: js_sys::Function, _reject| {
        let on_open = {
            let (flag, resolve) = (Rc::clone(&opened), resolve.clone());
            Closure::once_into_js(move |_event: Event| {
                flag.set(true);
                let _ = resolve.call0(&wasm_bindgen::JsValue::NULL);
            })
        };
        let on_fail = || {
            let resolve = resolve.clone();
            Closure::once_into_js(move |_event: Event| {
                let _ = resolve.call0(&wasm_bindgen::JsValue::NULL);
            })
        };
        websocket.set_onopen(Some(on_open.unchecked_ref()));
        websocket.set_onerror(Some(on_fail().unchecked_ref()));
        websocket.set_onclose(Some(on_fail().unchecked_ref()));
    });
    let _ = JsFuture::from(promise).await;
    websocket.set_onopen(None);
    websocket.set_onerror(None);
    websocket.set_onclose(None);
    if opened.get() {
        Ok(())
    } else {
        Err(NetworkError::ConnectionFailed(
            "Kaspa notification socket failed to open".into(),
        ))
    }
}

/// Send a Subscribe request with a replayable subscription body.
pub fn subscribe(key: u64, payload: &[u8]) -> Result<(), NetworkError> {
    let socket = socket(key)?;
    let id = socket.next_request_id.get();
    socket.next_request_id.set(id.wrapping_add(1));
    let frame = request::encode(&WrpcRequest {
        id,
        operation: Operation::Subscribe,
        payload,
    })?;
    let array = js_sys::Uint8Array::from(frame.as_slice());
    socket
        .websocket
        .send_with_array_buffer(&array.buffer())
        .map_err(|_| NetworkError::SendFailed)
}

/// Next raw frame (notification or subscription acknowledgement).
pub async fn next_frame(key: u64) -> Result<Vec<u8>, NetworkError> {
    loop {
        let socket = socket(key)?;
        if let Some(frame) = socket.frames.borrow_mut().pop_front() {
            return Ok(frame);
        }
        if socket.closed.get() {
            close(key);
            return Err(NetworkError::ConnectionFailed(
                "Kaspa notification socket closed".into(),
            ));
        }
        let promise = js_sys::Promise::new(&mut |resolve, _reject| {
            *socket.waiter.borrow_mut() = Some(resolve);
        });
        drop(socket);
        let _ = JsFuture::from(promise).await;
    }
}

/// Close and forget a notification socket.
pub fn close(key: u64) {
    if let Some(socket) = SOCKETS.with(|sockets| sockets.borrow_mut().remove(&key)) {
        socket.websocket.set_onmessage(None);
        socket.websocket.set_onclose(None);
        socket.websocket.set_onerror(None);
        let _ = socket.websocket.close();
    }
}

type KeySlot = std::sync::Mutex<Option<u64>>;

fn slot_key(slot: &KeySlot) -> Option<u64> {
    slot.lock().ok().and_then(|key| *key)
}

fn set_slot(slot: &KeySlot, value: Option<u64>) {
    if let Ok(mut key) = slot.lock() {
        *key = value;
    }
}

/// Subscribe on the transport's notification socket, opening it on first use.
pub(super) async fn subscribe_on(
    slot: &KeySlot,
    endpoint: &str,
    payload: &[u8],
) -> Result<Vec<u8>, NetworkError> {
    let key = match slot_key(slot) {
        Some(key) => key,
        None => {
            let key = open(endpoint).await?;
            set_slot(slot, Some(key));
            key
        }
    };
    subscribe(key, payload).map(|()| Vec::new())
}

/// Next frame from the transport's notification socket.
pub(super) async fn next_on(slot: &KeySlot) -> Result<Vec<u8>, NetworkError> {
    let key = slot_key(slot).ok_or_else(|| {
        NetworkError::UnexpectedResponse("no Kaspa notification subscription is active".into())
    })?;
    let frame = next_frame(key).await;
    if frame.is_err() {
        set_slot(slot, None);
    }
    frame
}

/// Close the transport's notification socket, if any.
pub(super) fn close_on(slot: &KeySlot) {
    if let Some(key) = slot_key(slot) {
        close(key);
    }
    set_slot(slot, None);
}
