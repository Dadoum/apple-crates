#[cfg(target_os = "linux")]
mod linux;
mod linux_libc;
#[cfg(all(target_family = "unix", not(target_os = "linux")))]
mod unix;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
use crate::linux::*;
#[cfg(all(target_family = "unix", not(target_os = "linux")))]
use crate::unix::*;
#[cfg(target_os = "windows")]
use crate::windows::*;
use adi::core_adi::{CoreADIADIProxy, CoreADIParameters, CoreADIProxy};
use adi::proxy::ADIError;
use elf_loader::elf_library::{Library, LibraryLoadingError, Symbol};
use elf_loader::{linux_cc, linux_fn};
use ouroboros::self_referencing;
use rand::Rng;
use std::collections::HashMap;
use std::error::Error;
use std::ffi::{c_char, c_void};
use std::fmt::Display;
use std::ops::Deref;

#[linux_cc]
fn android_arc4random() -> u32 {
    rand::rng().random()
}

#[linux_cc]
unsafe fn android_system_property_get(_name: *const char, value: *mut char) -> i32 {
    println!("android system_property_get");
    unsafe {
        let string = value as *mut [c_char; 2];
        *string = ['0' as c_char, '\0' as c_char];
    }
    1
}

#[self_referencing]
struct _AndroidCoreADIProxy<T: Deref<Target = [u8]> + 'static> {
    data: T,

    #[borrows(data)]
    #[covariant]
    library: Library<'this>,

    #[borrows(library)]
    #[covariant]
    dispatch_symbol: Symbol<'this, 'this, linux_fn! { fn(u32, *const CoreADIParameters) -> i32 }>,
}

pub struct AndroidCoreADIProxy<T: Deref<Target = [u8]> + 'static>(_AndroidCoreADIProxy<T>);

#[derive(Debug)]
pub enum AndroidCoreADILoadingError {
    InvalidLibrary(LibraryLoadingError),
    InvalidCoreADI,
    ADIError(ADIError),
}

impl Display for AndroidCoreADILoadingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AndroidCoreADILoadingError::InvalidLibrary(e) => {
                write!(f, "Provided data is not a valid library: {e}")
            }
            AndroidCoreADILoadingError::InvalidCoreADI => {
                write!(f, "Provided library is not a CoreADI library.")
            }
            AndroidCoreADILoadingError::ADIError(e) => {
                write!(f, "Failed to initialize CoreADI: {e}")
            }
        }
    }
}

impl Error for AndroidCoreADILoadingError {}

impl<T: Deref<Target = [u8]>> AndroidCoreADIProxy<T> {
    pub fn load_library(core_adi_data: T) -> Result<Self, AndroidCoreADILoadingError> {
        let mut hooks = HashMap::new();
        hooks.insert("arc4random", android_arc4random as *const c_void);
        hooks.insert("chmod", chmod as *const c_void);
        hooks.insert("close", close as *const c_void);
        hooks.insert("free", free as *const c_void);
        hooks.insert("fstat", fstat as *const c_void);
        hooks.insert("ftruncate", ftruncate as *const c_void);
        hooks.insert("gettimeofday", gettimeofday as *const c_void);
        hooks.insert("lstat", lstat as *const c_void);
        hooks.insert("malloc", malloc as *const c_void);
        hooks.insert("mkdir", mkdir as *const c_void);
        hooks.insert("open", open as *const c_void);
        hooks.insert("read", read as *const c_void);
        hooks.insert("strncpy", strncpy as *const c_void);
        hooks.insert("umask", umask as *const c_void);
        hooks.insert("write", write as *const c_void);
        hooks.insert(
            "__system_property_get",
            android_system_property_get as *const c_void,
        );
        hooks.insert("__errno", errno as *const c_void);
        hooks.insert("__errno_location", errno as *const c_void);

        // TODO: implement PThread functions
        hooks.insert("pthread_rwlock_destroy", nil_fn as *const c_void);
        hooks.insert("pthread_rwlock_init", nil_fn as *const c_void);
        hooks.insert("pthread_rwlock_rdlock", nil_fn as *const c_void);
        hooks.insert("pthread_rwlock_unlock", nil_fn as *const c_void);
        hooks.insert("pthread_rwlock_wrlock", nil_fn as *const c_void);

        let core_adi = AndroidCoreADIProxy(
            _AndroidCoreADIProxyTryBuilder {
                data: core_adi_data,
                library_builder: |data| {
                    Library::load(data, |sym| hooks.get(sym).copied())
                        .map_err(AndroidCoreADILoadingError::InvalidLibrary)
                },
                dispatch_symbol_builder: |library| {
                    library
                        .get("vdfut768ig")
                        .ok_or(AndroidCoreADILoadingError::InvalidCoreADI)
                },
            }
            .try_build()?,
        );

        core_adi
            .initialize()
            .map_err(AndroidCoreADILoadingError::ADIError)?;

        Ok(core_adi)
    }
}

impl<T: Deref<Target = [u8]>> Drop for AndroidCoreADIProxy<T> {
    fn drop(&mut self) {
        let _ = self.finalize();
    }
}

impl<T: Deref<Target = [u8]>> CoreADIProxy for AndroidCoreADIProxy<T> {
    unsafe fn dispatch(&self, function_code: u32, parameters: *const CoreADIParameters) -> i32 {
        (self.0.borrow_dispatch_symbol().ptr)(function_code, parameters)
    }
}

#[linux_cc]
unsafe fn nil_fn() -> i32 {
    0
}
