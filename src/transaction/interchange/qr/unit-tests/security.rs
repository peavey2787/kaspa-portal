use super::authorize_frame_session;

#[test]
fn accepts_first_frame_and_matching_session() {
    let a = [1u8; 8];
    assert!(authorize_frame_session(false, &[0u8; 8], 0, &a, 3).is_ok());
    assert!(authorize_frame_session(true, &a, 3, &a, 3).is_ok());
}

#[test]
fn rejects_session_splice_or_frame_count_change() {
    let a = [1u8; 8];
    let b = [2u8; 8];
    assert!(authorize_frame_session(true, &a, 3, &b, 3).is_err());
    assert!(authorize_frame_session(true, &a, 3, &a, 4).is_err());
}
