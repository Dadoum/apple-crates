#![allow(unsafe_op_in_unsafe_fn)]

use crate::linux_libc::*;
use elf_loader::linux_cc;
pub use libc::{
    chmod, close, free, ftruncate, gettimeofday, malloc, mkdir, read, strncpy, umask, write,
};
use std::mem;

#[linux_cc]
pub unsafe fn errno() -> *mut libc::c_int {
    // HACK we should also translate the errnos, but eh it works fine now
    libc::__error()
}

#[inline]
unsafe fn local_stat_to_linux(buf: libc::stat) -> stat {
    stat {
        st_dev: buf.st_dev as _,
        st_ino: buf.st_ino as _,
        st_nlink: buf.st_nlink as _,
        st_mode: buf.st_mode as _,
        st_uid: buf.st_uid as _,
        st_gid: buf.st_gid as _,
        st_rdev: buf.st_rdev as _,
        st_size: buf.st_size as _,
        st_blksize: buf.st_blksize as _,
        st_blocks: buf.st_blocks as _,
        st_atime: buf.st_atime as _,
        st_atime_nsec: buf.st_atime_nsec as _,
        st_mtime: buf.st_mtime as _,
        st_mtime_nsec: buf.st_mtime_nsec as _,
        st_ctime: buf.st_ctime as _,
        st_ctime_nsec: buf.st_ctime_nsec as _,
        ..mem::zeroed()
    }
}

#[linux_cc]
pub unsafe fn lstat(path: *const libc::c_char, buf: *mut stat) -> libc::c_int {
    let mut local_buf = mem::zeroed();
    let return_code = libc::lstat(path, &mut local_buf);
    *buf = local_stat_to_linux(local_buf);
    return_code
}

#[linux_cc]
pub unsafe fn fstat(fildes: libc::c_int, buf: *mut stat) -> libc::c_int {
    let mut local_buf = mem::zeroed();
    let return_code = libc::fstat(fildes, &mut local_buf);
    *buf = local_stat_to_linux(local_buf);
    return_code
}

#[linux_cc]
pub unsafe fn open(path: *const libc::c_char, oflag: libc::c_int) -> libc::c_int {
    let mut local_flag = 0;

    if oflag & 0b11 == O_WRONLY {
        local_flag = libc::O_RDWR;
    }
    if oflag & 0b11 == O_RDWR {
        local_flag = libc::O_RDWR;
    }
    if oflag & 0b11 == O_RDONLY {
        local_flag = libc::O_RDWR;
    }

    if oflag & O_CREAT != 0 {
        local_flag |= libc::O_CREAT;
    }
    if oflag & O_NOFOLLOW != 0 {
        local_flag |= libc::O_NOFOLLOW;
    }

    libc::open(path, local_flag, 0o777)
}
