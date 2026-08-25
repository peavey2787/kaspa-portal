//! Session-binding checks for multi-frame QR transfers.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionError {
    MixedSession,
    FrameCountChanged,
}

pub(crate) fn authorize_frame_session(
    session_active: bool,
    current_session_id: &[u8],
    current_total_frames: u8,
    incoming_session_id: &[u8],
    incoming_total_frames: u8,
) -> Result<(), SessionError> {
    if !session_active {
        return Ok(());
    }
    if current_session_id != incoming_session_id {
        return Err(SessionError::MixedSession);
    }
    if current_total_frames != incoming_total_frames {
        return Err(SessionError::FrameCountChanged);
    }
    Ok(())
}

#[cfg(test)]
#[path = "unit-tests/security.rs"]
mod unit_tests;
