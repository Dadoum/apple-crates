//! POSIX compatibility layer for macOS/Linux differences
//! Handles struct layout differences between Android x86_64 and host system
#![allow(unsafe_op_in_unsafe_fn)]

#[cfg(target_os = "macos")]
use libc::{
    O_CREAT, O_RDONLY, O_RDWR, O_WRONLY, fstat as fstat_native, lstat as lstat_native,
    open as open_native, stat as stat_native,
};

/// Linux x86_64 stat structure layout (for Android compatibility)
#[repr(C)]
#[derive(Debug, Default)]
pub struct StatLinux {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    __pad0: i32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    __unused: [i64; 3],
}

#[cfg(target_os = "macos")]
fn convert_stat(st: &libc::stat) -> StatLinux {
    StatLinux {
        st_dev: st.st_dev as u64,
        st_ino: st.st_ino as u64,
        st_nlink: st.st_nlink as u64,
        st_mode: st.st_mode as u32,
        st_uid: st.st_uid as u32,
        st_gid: st.st_gid as u32,
        __pad0: 0,
        st_rdev: st.st_rdev as u64,
        st_size: st.st_size as i64,
        st_blksize: st.st_blksize as i64,
        st_blocks: st.st_blocks as i64,
        st_atime: st.st_atime as i64,
        st_atime_nsec: st.st_atime_nsec as i64,
        st_mtime: st.st_mtime as i64,
        st_mtime_nsec: st.st_mtime_nsec as i64,
        st_ctime: st.st_ctime as i64,
        st_ctime_nsec: st.st_ctime_nsec as i64,
        __unused: [0, 0, 0],
    }
}

/// lstat wrapper that converts to Linux stat layout
#[cfg(target_os = "macos")]
pub unsafe extern "C" fn lstat_linux(
    path: *const libc::c_char,
    buf: *mut StatLinux,
) -> libc::c_int {
    let mut st: libc::stat = std::mem::zeroed();
    if lstat_native(path, &mut st) != 0 {
        return -1;
    }
    *buf = convert_stat(&st);
    0
}

/// fstat wrapper that converts to Linux stat layout
#[cfg(target_os = "macos")]
pub unsafe extern "C" fn fstat_linux(fd: libc::c_int, buf: *mut StatLinux) -> libc::c_int {
    let mut st: libc::stat = std::mem::zeroed();
    if fstat_native(fd, &mut st) != 0 {
        return -1;
    }
    *buf = convert_stat(&st);
    0
}

/// stat wrapper that converts to Linux stat layout
#[cfg(target_os = "macos")]
pub unsafe extern "C" fn stat_linux(path: *const libc::c_char, buf: *mut StatLinux) -> libc::c_int {
    let mut st: libc::stat = std::mem::zeroed();
    if stat_native(path, &mut st) != 0 {
        return -1;
    }
    *buf = convert_stat(&st);
    0
}

/// open wrapper that translates Linux flags to macOS
#[cfg(target_os = "macos")]
pub unsafe extern "C" fn open_linux(
    path: *const libc::c_char,
    oflag: libc::c_int,
    mode: libc::mode_t,
) -> libc::c_int {
    // Linux O_* flags to macOS translation
    let mut translated_flag = 0;

    // O_CREAT is 0o100 on Linux
    if oflag & 0o100 != 0 {
        translated_flag |= O_CREAT;
    }

    // O_RDONLY=0, O_WRONLY=1, O_RDWR=2 are same on both
    if oflag & 0o3 == 1 {
        translated_flag |= O_WRONLY;
    } else if oflag & 0o3 == 2 {
        translated_flag |= O_RDWR;
    } else {
        translated_flag |= O_RDONLY;
    }

    // O_TRUNC is 0o1000 on Linux, same on macOS
    if oflag & 0o1000 != 0 {
        translated_flag |= libc::O_TRUNC;
    }

    // O_APPEND is 0o2000 on Linux
    if oflag & 0o2000 != 0 {
        translated_flag |= libc::O_APPEND;
    }

    // O_EXCL is 0o200 on Linux
    if oflag & 0o200 != 0 {
        translated_flag |= libc::O_EXCL;
    }

    open_native(path, translated_flag, mode as libc::c_uint)
}

// On Linux, just use native functions
#[cfg(not(target_os = "macos"))]
pub use libc::{
    fstat as fstat_linux, lstat as lstat_linux, open as open_linux, stat as stat_linux,
};
