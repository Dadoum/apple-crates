#![allow(non_camel_case_types)]
#![allow(dead_code)]

#[cfg(target_pointer_width = "32")]
#[repr(C)]
pub struct stat {
    pub st_dev: libc::c_ulonglong,
    pub __pad0: [libc::c_uchar; 4],
    pub __st_ino: ino_t,
    pub st_mode: libc::c_uint,
    pub st_nlink: nlink_t,
    pub st_uid: uid_t,
    pub st_gid: gid_t,
    pub st_rdev: libc::c_ulonglong,
    pub __pad3: [libc::c_uchar; 4],
    pub st_size: libc::c_longlong,
    pub st_blksize: blksize_t,
    pub st_blocks: libc::c_ulonglong,
    pub st_atime: isize,
    pub st_atime_nsec: isize,
    pub st_mtime: isize,
    pub st_mtime_nsec: isize,
    pub st_ctime: isize,
    pub st_ctime_nsec: isize,
    pub st_ino: libc::c_ulonglong,
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
pub struct stat {
    pub st_dev: dev_t,
    pub st_ino: ino_t,
    pub st_mode: libc::c_uint,
    pub st_nlink: nlink_t,
    pub st_uid: uid_t,
    pub st_gid: gid_t,
    pub st_rdev: dev_t,
    pub __pad1: usize,
    pub st_size: off64_t,
    pub st_blksize: libc::c_int,
    pub __pad2: libc::c_int,
    pub st_blocks: isize,
    pub st_atime: time_t,
    pub st_atime_nsec: isize,
    pub st_mtime: time_t,
    pub st_mtime_nsec: isize,
    pub st_ctime: time_t,
    pub st_ctime_nsec: isize,
    pub __unused4: libc::c_uint,
    pub __unused5: libc::c_uint,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct stat {
    pub st_dev: dev_t,
    pub st_ino: ino_t,
    pub st_nlink: usize,
    pub st_mode: libc::c_uint,
    pub st_uid: uid_t,
    pub st_gid: gid_t,
    pub st_rdev: dev_t,
    pub st_size: off64_t,
    pub st_blksize: isize,
    pub st_blocks: isize,
    pub st_atime: isize,
    pub st_atime_nsec: isize,
    pub st_mtime: isize,
    pub st_mtime_nsec: isize,
    pub st_ctime: isize,
    pub st_ctime_nsec: isize,
    pub __unused: [isize; 3],
}

pub const O_RDONLY: libc::c_int = 0;
pub const O_WRONLY: libc::c_int = 1;
pub const O_RDWR: libc::c_int = 2;

pub const O_CREAT: libc::c_int = 64;

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub const O_NOFOLLOW: libc::c_int = 0x20000;
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
pub const O_NOFOLLOW: libc::c_int = 0x8000;

pub type dev_t = usize;
pub type ino_t = usize;
pub type nlink_t = u32;
pub type uid_t = u32;
pub type gid_t = u32;

#[cfg(target_pointer_width = "32")]
pub type off64_t = libc::c_longlong;
#[cfg(target_pointer_width = "64")]
pub type off64_t = i64;

#[cfg(target_pointer_width = "64")]
pub type mode_t = u32;
#[cfg(target_pointer_width = "32")]
pub type mode_t = u16;

pub type time_t = isize;

pub type suseconds_t = i64;

#[repr(C)]
pub struct timeval {
    pub tv_sec: time_t,
    pub tv_usec: suseconds_t,
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    #[test]
    fn linux_abi_layout_is_independent_of_windows_long_width() {
        assert_eq!(std::mem::size_of::<stat>(), 144);
        assert_eq!(std::mem::offset_of!(stat, st_size), 48);
        assert_eq!(std::mem::offset_of!(stat, st_atime), 72);
        assert_eq!(std::mem::size_of::<timeval>(), 16);
        assert_eq!(std::mem::offset_of!(timeval, tv_usec), 8);
    }
}
