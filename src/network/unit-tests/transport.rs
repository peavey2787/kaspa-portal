#[cfg(not(target_arch = "wasm32"))]
#[test]
fn native_transport_future_contract_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<crate::network::transport::traits::TransportFuture<'static>>();
    assert_send::<crate::network::transport::traits::NotificationFuture<'static>>();
}
