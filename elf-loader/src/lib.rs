mod elf_hash_table;
pub mod elf_library;

pub use sysv64::sysv64 as linux_cc;

#[cfg(target_arch = "x86_64")]
#[macro_export]
macro_rules! linux_fn {
    (unsafe fn ($($args:tt)*) $(-> $ret:ty)?) => {
        unsafe extern "sysv64" fn($($args)*) $(-> $ret)?
    };

    (fn ($($args:tt)*) $(-> $ret:ty)?) => {
        extern "sysv64" fn($($args)*) $(-> $ret)?
    };
}

#[cfg(not(target_arch = "x86_64"))]
#[macro_export]
macro_rules! linux_fn {
    (unsafe fn ($($args:tt)*) $(-> $ret:ty)?) => {
        unsafe extern "C" fn($($args)*) $(-> $ret)?
    };

    (fn ($($args:tt)*) $(-> $ret:ty)?) => {
        extern "C" fn($($args)*) $(-> $ret)?
    };
}
