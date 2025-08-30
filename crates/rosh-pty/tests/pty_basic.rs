#[cfg(unix)]
#[test]
fn allocate_and_resize_pty() {
    use rosh_pty::pty::Pty;
    let mut pty = Pty::new().expect("allocate pty");
    // Basic resize should succeed
    pty.resize(30, 100).expect("resize");
    // Master FD should still be valid
    assert!(pty.master().has_fd());
}
