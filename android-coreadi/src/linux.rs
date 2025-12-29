use elf_loader::linux_cc;
pub use libc::{
    chmod, close, free, fstat, ftruncate, gettimeofday, lstat, malloc, mkdir, open, read, strncpy,
    umask, write,
};

#[linux_cc]
pub unsafe fn errno() -> *mut libc::c_int {
    unsafe { libc::__errno_location() }
}
