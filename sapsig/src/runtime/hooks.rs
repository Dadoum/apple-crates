//! System call hooks for Android library compatibility
#![allow(function_casts_as_integer)]
#![allow(unsafe_op_in_unsafe_fn)]

use crate::elf_loader::{
    ensure_registered_library_initialized, is_registered_library_handle,
    lookup_registered_library_handle, lookup_symbol_in_registered_library,
};
use crate::posix_compat;
use rand::Rng;
use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::{Mutex, OnceLock};

lazy_static::lazy_static! {
    pub static ref GLOBAL_HOOKS: Mutex<HashMap<String, usize>> = Mutex::new(HashMap::new());
}

static mut DYNAMIC_STUB_STORAGE: [u8; 0x4000] = [0; 0x4000];
static CTYPE_TABLE_STUB: [u16; 384] = [0; 384];
const NDK_STRING_SHORT_MAX: usize = 22;
const MP_DATA_TAG: u64 = 0x5841_534d_5044_4154; // XASMPDAT
const CF_DATA_TAG: u64 = 0x5841_5343_4644_4154; // XASCFDAT
const CF_STRING_TAG: u64 = 0x5841_5343_4653_5452; // XASCFSTR

#[repr(C)]
struct MpDataStub {
    tag: u64,
    len: usize,
    cap: usize,
    ptr: *mut u8,
}

#[repr(C)]
struct CfDataStub {
    tag: u64,
    len: usize,
    ptr: *mut u8,
}

#[repr(C)]
struct CfStringStub {
    tag: u64,
    len: usize,
    ptr: *mut u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreFoundationMode {
    /// Prefer symbols from loaded libraries; unresolved symbols fallback to stubs.
    Auto,
    /// Same as auto, but proactively probes macOS CoreFoundation symbols when available.
    Native,
    /// Force stub symbols on all platforms.
    Stub,
}

impl CoreFoundationMode {
    fn from_env() -> Self {
        let value = std::env::var("XAS_CF_MODE")
            .unwrap_or_else(|_| "auto".to_string())
            .to_ascii_lowercase();
        match value.as_str() {
            "native" => Self::Native,
            "stub" => Self::Stub,
            _ => Self::Auto,
        }
    }
}

fn env_default_true_flag(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| {
            let v = v.to_ascii_lowercase();
            !(v == "0" || v == "false" || v == "off")
        })
        .unwrap_or(true)
}

/// Initialize all required hooks for Android library compatibility
pub fn setup_hooks() {
    setup_hooks_with_mode(CoreFoundationMode::from_env());
}

/// Initialize hooks with explicit CoreFoundation strategy.
pub fn setup_hooks_with_mode(cf_mode: CoreFoundationMode) {
    let mut hooks = GLOBAL_HOOKS.lock().unwrap();

    // errno
    hooks.insert("__errno".to_string(), errno_location as usize);
    hooks.insert("__errno_location".to_string(), errno_location as usize);

    // Random
    hooks.insert("arc4random".to_string(), arc4random as usize);
    hooks.insert("arc4random_buf".to_string(), arc4random_buf as usize);

    // Android specific
    hooks.insert(
        "__system_property_get".to_string(),
        system_property_get as usize,
    );
    hooks.insert(
        "__android_log_print".to_string(),
        android_log_print_stub as usize,
    );
    hooks.insert(
        "__android_log_write".to_string(),
        android_log_write as usize,
    );
    hooks.insert(
        "__android_log_vprint".to_string(),
        android_log_vprint as usize,
    );

    // C++ runtime / ABI
    insert_process_symbol_or_stub(&mut hooks, "__cxa_atexit", cxa_atexit as usize);
    insert_process_symbol_or_stub(&mut hooks, "__cxa_finalize", cxa_finalize as usize);
    insert_process_symbol_or_stub(
        &mut hooks,
        "__cxa_thread_atexit_impl",
        cxa_thread_atexit_impl as usize,
    );

    // dl* functions
    hooks.insert("dlopen".to_string(), hook_dlopen as usize);
    hooks.insert("dlsym".to_string(), hook_dlsym as usize);
    hooks.insert("dlclose".to_string(), hook_dlclose as usize);
    hooks.insert("dlerror".to_string(), hook_dlerror as usize);

    // POSIX file operations
    // On macOS, use posix_compat wrappers that translate struct layouts
    // (Android expects Linux stat layout = 144 bytes, macOS stat is different)
    hooks.insert("open".to_string(), posix_compat::open_linux as usize);
    hooks.insert("close".to_string(), libc::close as usize);
    hooks.insert("read".to_string(), libc::read as usize);
    hooks.insert("write".to_string(), libc::write as usize);
    hooks.insert("lseek".to_string(), libc::lseek as usize);
    hooks.insert("lseek64".to_string(), libc::lseek as usize);
    hooks.insert("fstat".to_string(), posix_compat::fstat_linux as usize);
    hooks.insert("fstat64".to_string(), posix_compat::fstat_linux as usize);
    hooks.insert("lstat".to_string(), posix_compat::lstat_linux as usize);
    hooks.insert("stat".to_string(), posix_compat::stat_linux as usize);
    hooks.insert("ftruncate".to_string(), libc::ftruncate as usize);
    hooks.insert("fsync".to_string(), libc::fsync as usize);
    hooks.insert("fdatasync".to_string(), libc::fsync as usize);
    hooks.insert("dup".to_string(), libc::dup as usize);
    hooks.insert("dup2".to_string(), libc::dup2 as usize);
    hooks.insert("pipe".to_string(), libc::pipe as usize);
    hooks.insert("fcntl".to_string(), libc::fcntl as usize);
    hooks.insert("ioctl".to_string(), libc::ioctl as usize);

    // Directory operations
    hooks.insert("mkdir".to_string(), libc::mkdir as usize);
    hooks.insert("rmdir".to_string(), libc::rmdir as usize);
    hooks.insert("chdir".to_string(), libc::chdir as usize);
    hooks.insert("getcwd".to_string(), libc::getcwd as usize);
    hooks.insert("opendir".to_string(), libc::opendir as usize);
    hooks.insert("readdir".to_string(), libc::readdir as usize);
    hooks.insert("closedir".to_string(), libc::closedir as usize);

    // File permissions
    hooks.insert("chmod".to_string(), libc::chmod as usize);
    hooks.insert("fchmod".to_string(), libc::fchmod as usize);
    hooks.insert("umask".to_string(), libc::umask as usize);
    hooks.insert("access".to_string(), libc::access as usize);
    hooks.insert("unlink".to_string(), libc::unlink as usize);
    hooks.insert("rename".to_string(), libc::rename as usize);
    hooks.insert("link".to_string(), libc::link as usize);
    hooks.insert("symlink".to_string(), libc::symlink as usize);
    hooks.insert("readlink".to_string(), libc::readlink as usize);

    // Memory
    hooks.insert("malloc".to_string(), libc::malloc as usize);
    hooks.insert("calloc".to_string(), libc::calloc as usize);
    hooks.insert("realloc".to_string(), libc::realloc as usize);
    hooks.insert("free".to_string(), libc::free as usize);
    hooks.insert("posix_memalign".to_string(), libc::posix_memalign as usize);
    hooks.insert("mmap".to_string(), libc::mmap as usize);
    hooks.insert("mmap64".to_string(), libc::mmap as usize);
    hooks.insert("munmap".to_string(), libc::munmap as usize);
    hooks.insert("mprotect".to_string(), libc::mprotect as usize);
    hooks.insert("memcpy".to_string(), libc::memcpy as usize);
    hooks.insert("memmove".to_string(), libc::memmove as usize);
    hooks.insert("memset".to_string(), libc::memset as usize);
    hooks.insert("memcmp".to_string(), libc::memcmp as usize);

    // String operations
    hooks.insert("strlen".to_string(), libc::strlen as usize);
    hooks.insert("strcpy".to_string(), libc::strcpy as usize);
    hooks.insert("strncpy".to_string(), libc::strncpy as usize);
    hooks.insert("strcat".to_string(), libc::strcat as usize);
    hooks.insert("strncat".to_string(), libc::strncat as usize);
    hooks.insert("strcmp".to_string(), libc::strcmp as usize);
    hooks.insert("strncmp".to_string(), libc::strncmp as usize);
    hooks.insert("strchr".to_string(), libc::strchr as usize);
    hooks.insert("strrchr".to_string(), libc::strrchr as usize);
    hooks.insert("strstr".to_string(), libc::strstr as usize);
    hooks.insert("strdup".to_string(), libc::strdup as usize);
    hooks.insert("strerror".to_string(), libc::strerror as usize);
    hooks.insert("__strlen_chk".to_string(), strlen_chk_stub as usize);
    hooks.insert("__strchr_chk".to_string(), strchr_chk_stub as usize);
    hooks.insert("__strncpy_chk2".to_string(), strncpy_chk2_stub as usize);
    hooks.insert("memrchr".to_string(), memrchr_stub as usize);

    // Time functions
    hooks.insert("time".to_string(), libc::time as usize);
    hooks.insert("gettimeofday".to_string(), libc::gettimeofday as usize);
    hooks.insert("clock_gettime".to_string(), libc::clock_gettime as usize);
    hooks.insert("nanosleep".to_string(), libc::nanosleep as usize);
    hooks.insert("usleep".to_string(), libc::usleep as usize);
    hooks.insert("sleep".to_string(), libc::sleep as usize);

    // Process
    hooks.insert("getpid".to_string(), libc::getpid as usize);
    hooks.insert("getuid".to_string(), libc::getuid as usize);
    hooks.insert("geteuid".to_string(), libc::geteuid as usize);
    hooks.insert("getgid".to_string(), libc::getgid as usize);
    hooks.insert("getegid".to_string(), libc::getegid as usize);
    hooks.insert("gettid".to_string(), gettid_stub as usize);
    hooks.insert("fork".to_string(), libc::fork as usize);
    hooks.insert("exit".to_string(), libc::exit as usize);
    hooks.insert("_exit".to_string(), libc::_exit as usize);
    hooks.insert("abort".to_string(), libc::abort as usize);

    // Pthread
    let pthread_mutex_stub_enabled = env_default_true_flag("XAS_PTHREAD_MUTEX_STUB");
    let pthread_mutex_init_ptr = if pthread_mutex_stub_enabled {
        pthread_mutex_init_stub as usize
    } else {
        libc::pthread_mutex_init as usize
    };
    let pthread_mutex_destroy_ptr = if pthread_mutex_stub_enabled {
        pthread_mutex_destroy_stub as usize
    } else {
        libc::pthread_mutex_destroy as usize
    };
    let pthread_mutex_lock_ptr = if pthread_mutex_stub_enabled {
        pthread_mutex_lock_stub as usize
    } else {
        libc::pthread_mutex_lock as usize
    };
    let pthread_mutex_unlock_ptr = if pthread_mutex_stub_enabled {
        pthread_mutex_unlock_stub as usize
    } else {
        libc::pthread_mutex_unlock as usize
    };
    let pthread_mutex_trylock_ptr = if pthread_mutex_stub_enabled {
        pthread_mutex_trylock_stub as usize
    } else {
        libc::pthread_mutex_trylock as usize
    };
    hooks.insert("pthread_self".to_string(), libc::pthread_self as usize);
    hooks.insert("pthread_create".to_string(), libc::pthread_create as usize);
    hooks.insert("pthread_join".to_string(), libc::pthread_join as usize);
    hooks.insert("pthread_detach".to_string(), libc::pthread_detach as usize);
    hooks.insert("pthread_mutex_init".to_string(), pthread_mutex_init_ptr);
    hooks.insert(
        "pthread_mutex_destroy".to_string(),
        pthread_mutex_destroy_ptr,
    );
    hooks.insert("pthread_mutex_lock".to_string(), pthread_mutex_lock_ptr);
    hooks.insert("pthread_mutex_unlock".to_string(), pthread_mutex_unlock_ptr);
    hooks.insert(
        "pthread_mutex_trylock".to_string(),
        pthread_mutex_trylock_ptr,
    );
    hooks.insert(
        "pthread_cond_init".to_string(),
        libc::pthread_cond_init as usize,
    );
    hooks.insert(
        "pthread_cond_destroy".to_string(),
        libc::pthread_cond_destroy as usize,
    );
    hooks.insert(
        "pthread_cond_wait".to_string(),
        libc::pthread_cond_wait as usize,
    );
    hooks.insert(
        "pthread_cond_signal".to_string(),
        libc::pthread_cond_signal as usize,
    );
    hooks.insert(
        "pthread_cond_broadcast".to_string(),
        libc::pthread_cond_broadcast as usize,
    );
    hooks.insert(
        "pthread_rwlock_init".to_string(),
        libc::pthread_rwlock_init as usize,
    );
    hooks.insert(
        "pthread_rwlock_destroy".to_string(),
        libc::pthread_rwlock_destroy as usize,
    );
    hooks.insert(
        "pthread_rwlock_rdlock".to_string(),
        libc::pthread_rwlock_rdlock as usize,
    );
    hooks.insert(
        "pthread_rwlock_wrlock".to_string(),
        libc::pthread_rwlock_wrlock as usize,
    );
    hooks.insert(
        "pthread_rwlock_unlock".to_string(),
        libc::pthread_rwlock_unlock as usize,
    );
    hooks.insert("pthread_once".to_string(), android_pthread_once as usize);
    hooks.insert(
        "pthread_key_create".to_string(),
        libc::pthread_key_create as usize,
    );
    hooks.insert(
        "pthread_key_delete".to_string(),
        libc::pthread_key_delete as usize,
    );
    hooks.insert(
        "pthread_getspecific".to_string(),
        libc::pthread_getspecific as usize,
    );
    hooks.insert(
        "pthread_setspecific".to_string(),
        libc::pthread_setspecific as usize,
    );

    // Socket
    hooks.insert("socket".to_string(), libc::socket as usize);
    hooks.insert("bind".to_string(), libc::bind as usize);
    hooks.insert("listen".to_string(), libc::listen as usize);
    hooks.insert("accept".to_string(), libc::accept as usize);
    hooks.insert("connect".to_string(), libc::connect as usize);
    hooks.insert("send".to_string(), libc::send as usize);
    hooks.insert("recv".to_string(), libc::recv as usize);
    hooks.insert("sendto".to_string(), libc::sendto as usize);
    hooks.insert("recvfrom".to_string(), libc::recvfrom as usize);
    hooks.insert("setsockopt".to_string(), libc::setsockopt as usize);
    hooks.insert("getsockopt".to_string(), libc::getsockopt as usize);
    hooks.insert("shutdown".to_string(), libc::shutdown as usize);
    hooks.insert("getaddrinfo".to_string(), libc::getaddrinfo as usize);
    hooks.insert("freeaddrinfo".to_string(), libc::freeaddrinfo as usize);
    hooks.insert("getnameinfo".to_string(), libc::getnameinfo as usize);

    // File locking
    hooks.insert("flock".to_string(), libc::flock as usize);

    // Misc
    hooks.insert("getenv".to_string(), libc::getenv as usize);
    hooks.insert("setenv".to_string(), libc::setenv as usize);
    hooks.insert("unsetenv".to_string(), libc::unsetenv as usize);
    hooks.insert("sysconf".to_string(), libc::sysconf as usize);
    hooks.insert("__read_chk".to_string(), read_chk_stub as usize);
    hooks.insert("__open_2".to_string(), open_2_stub as usize);
    hooks.insert("__FD_SET_chk".to_string(), fd_set_chk_stub as usize);
    hooks.insert("__FD_CLR_chk".to_string(), fd_clr_chk_stub as usize);
    hooks.insert("__FD_ISSET_chk".to_string(), fd_isset_chk_stub as usize);

    // Linux-specific stubs
    hooks.insert("dl_iterate_phdr".to_string(), dl_iterate_phdr_stub as usize);
    hooks.insert("getauxval".to_string(), getauxval_stub as usize);
    hooks.insert("posix_fadvise".to_string(), posix_fadvise_stub as usize);
    hooks.insert("mremap".to_string(), mremap_stub as usize);
    hooks.insert("eventfd".to_string(), eventfd_stub as usize);
    hooks.insert("eventfd_read".to_string(), eventfd_read_stub as usize);
    hooks.insert("eventfd_write".to_string(), eventfd_write_stub as usize);
    hooks.insert("epoll_create".to_string(), epoll_create_stub as usize);
    hooks.insert("epoll_ctl".to_string(), epoll_ctl_stub as usize);
    hooks.insert("epoll_wait".to_string(), epoll_wait_stub as usize);
    hooks.insert("timerfd_create".to_string(), timerfd_create_stub as usize);
    hooks.insert("timerfd_settime".to_string(), timerfd_settime_stub as usize);
    hooks.insert("signalfd".to_string(), signalfd_stub as usize);
    hooks.insert("sem_timedwait".to_string(), sem_timedwait_stub as usize);

    // C++ exception handling
    insert_process_symbol_or_stub(&mut hooks, "__cxa_begin_catch", cxa_begin_catch as usize);
    insert_process_symbol_or_stub(&mut hooks, "__cxa_end_catch", cxa_end_catch as usize);
    insert_process_symbol_or_stub(
        &mut hooks,
        "__cxa_allocate_exception",
        cxa_allocate_exception as usize,
    );
    insert_process_symbol_or_stub(&mut hooks, "__cxa_throw", cxa_throw as usize);
    insert_process_symbol_or_stub(&mut hooks, "__cxa_rethrow", cxa_rethrow as usize);
    insert_process_symbol_or_stub(
        &mut hooks,
        "__gxx_personality_v0",
        gxx_personality_v0 as usize,
    );
    insert_process_symbol_or_stub(&mut hooks, "_Unwind_Resume", unwind_resume as usize);

    // C++ static init guard
    insert_process_symbol_or_stub(
        &mut hooks,
        "__cxa_guard_acquire",
        cxa_guard_acquire as usize,
    );
    insert_process_symbol_or_stub(
        &mut hooks,
        "__cxa_guard_release",
        cxa_guard_release as usize,
    );
    insert_process_symbol_or_stub(&mut hooks, "__cxa_guard_abort", cxa_guard_abort as usize);
    hooks.insert("__cxa_pure_virtual".to_string(), cxa_pure_virtual as usize);
    hooks.insert(
        "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6assignEPKc".to_string(),
        ndk_string_assign as usize,
    );
    hooks.insert(
        "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev".to_string(),
        ndk_string_dtor as usize,
    );
    hooks.insert(
        "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev".to_string(),
        ndk_string_dtor as usize,
    );

    // Math (via libm, usually linked)
    hooks.insert("sin".to_string(), libm_sin as usize);
    hooks.insert("cos".to_string(), libm_cos as usize);
    hooks.insert("tan".to_string(), libm_tan as usize);
    hooks.insert("sqrt".to_string(), libm_sqrt as usize);
    hooks.insert("pow".to_string(), libm_pow as usize);
    hooks.insert("log".to_string(), libm_log as usize);
    hooks.insert("exp".to_string(), libm_exp as usize);
    hooks.insert("floor".to_string(), libm_floor as usize);
    hooks.insert("ceil".to_string(), libm_ceil as usize);
    hooks.insert("fabs".to_string(), libm_fabs as usize);
    hooks.insert("sincos".to_string(), sincos_stub as usize);
    hooks.insert("inflateInit_".to_string(), zlib_inflate_init_stub as usize);
    hooks.insert(
        "inflateInit2_".to_string(),
        zlib_inflate_init2_stub as usize,
    );
    hooks.insert("inflate".to_string(), zlib_inflate_stub as usize);
    hooks.insert("inflateEnd".to_string(), zlib_inflate_end_stub as usize);
    hooks.insert("zlibVersion".to_string(), zlib_version_stub as usize);
    hooks.insert(
        "deflateInit2_".to_string(),
        zlib_deflate_init2_stub as usize,
    );
    hooks.insert("deflate".to_string(), zlib_deflate_stub as usize);
    hooks.insert("deflateEnd".to_string(), zlib_deflate_end_stub as usize);
    hooks.insert("crc32".to_string(), crc32_stub as usize);
    hooks.insert("gzopen".to_string(), gzopen_stub as usize);
    hooks.insert("gzdopen".to_string(), gzdopen_stub as usize);
    hooks.insert("gzread".to_string(), gzread_stub as usize);
    hooks.insert("gzwrite".to_string(), gzwrite_stub as usize);
    hooks.insert("gzclose".to_string(), gzclose_stub as usize);
    hooks.insert("gzdirect".to_string(), gzdirect_stub as usize);
    hooks.insert("__get_h_errno".to_string(), get_h_errno_stub as usize);
    hooks.insert(
        "__ctype_get_mb_cur_max".to_string(),
        ctype_get_mb_cur_max_stub as usize,
    );
    hooks.insert(
        "android_set_abort_message".to_string(),
        android_set_abort_message_stub as usize,
    );
    hooks.insert("_ctype_".to_string(), CTYPE_TABLE_STUB.as_ptr() as usize);
    hooks.insert(
        "malloc_usable_size".to_string(),
        malloc_usable_size_stub as usize,
    );
    hooks.insert("ppoll".to_string(), ppoll_stub as usize);

    // CoreFoundation symbols used by libstoreservicescore.so.
    register_corefoundation_hooks(&mut hooks, cf_mode);

    // Mescal::sign(std::string) enters a mediaplatform debug-log branch first.
    // In host-mode emulation this branch often pulls in additional formatting paths;
    // default to disabled unless explicitly opted back in.
    let disable_mp_debug_log = std::env::var("XAS_MP_DISABLE_DEBUG_LOG")
        .ok()
        .map(|v| {
            let v = v.to_ascii_lowercase();
            !(v == "0" || v == "false" || v == "off")
        })
        .unwrap_or(true);
    if disable_mp_debug_log {
        hooks.insert(
            "_ZN13mediaplatform26DebugLogEnabledForPriorityENS_11LogPriorityE".to_string(),
            mediaplatform_debug_log_disabled as usize,
        );
    }

    // Optional mediaplatform::Data/Base64 stubs for ABI probing only.
    // Default is disabled so preloaded libCoreFP exports can be resolved.
    let mediaplatform_stub_enabled = std::env::var("XAS_MP_STUB")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if mediaplatform_stub_enabled {
        hooks.insert(
            "_ZN13mediaplatform4DataC1EPKvmb".to_string(),
            mediaplatform_data_ctor_from_bytes_stub as usize,
        );
        hooks.insert(
            "_ZN13mediaplatform4DataC1Ev".to_string(),
            mediaplatform_data_ctor_default_stub as usize,
        );
        hooks.insert(
            "_ZN13mediaplatform4DataD1Ev".to_string(),
            mediaplatform_data_dtor_stub as usize,
        );
        hooks.insert(
            "_ZN13mediaplatform4DataD2Ev".to_string(),
            mediaplatform_data_dtor_stub as usize,
        );
        hooks.insert(
            "_ZNK13mediaplatform4Data5bytesEv".to_string(),
            mediaplatform_data_bytes_stub as usize,
        );
        hooks.insert(
            "_ZNK13mediaplatform4Data6lengthEv".to_string(),
            mediaplatform_data_length_stub as usize,
        );
        hooks.insert(
            "_ZN13mediaplatform12Base64EncodeEPK8__CFData".to_string(),
            mediaplatform_base64_encode_stub as usize,
        );
    }

    // Base64 bridge path can optionally force caller-provided CF object stubs for ABI probing.
    // Default is off so real libCoreFoundation symbols can be exercised.
    let bridge_stub_enabled = std::env::var("XAS_CF_BRIDGE_STUB")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if bridge_stub_enabled || matches!(cf_mode, CoreFoundationMode::Stub) {
        hooks.insert(
            "CFDataCreateWithBytesNoCopy".to_string(),
            cf_data_create_with_bytes_no_copy_stub as usize,
        );
        hooks.insert(
            "CFDataGetBytePtr".to_string(),
            cf_data_get_byte_ptr_stub as usize,
        );
        hooks.insert(
            "CFDataGetLength".to_string(),
            cf_data_get_length_stub as usize,
        );
        hooks.insert(
            "CFStringGetLength".to_string(),
            cf_string_get_length_stub as usize,
        );
        hooks.insert(
            "CFStringGetMaximumSizeForEncoding".to_string(),
            cf_string_get_maximum_size_for_encoding_stub as usize,
        );
        hooks.insert(
            "CFStringGetCString".to_string(),
            cf_string_get_cstring_stub as usize,
        );
        hooks.insert("CFRelease".to_string(), cf_release_stub as usize);
        hooks.insert("CFRetain".to_string(), cf_retain_stub as usize);
    }
}

/// Fallback resolver for symbols that are not present in host libc/frameworks.
/// This avoids unresolved symbols being hard-mapped to address 0.
pub fn resolve_dynamic_symbol_fallback(name: &str) -> Option<usize> {
    if let Some(kind) = corefoundation_symbol_kind(name) {
        return Some(corefoundation_stub_addr(kind));
    }

    if is_corefoundation_constant(name) {
        return Some(dynamic_stub_data_ptr());
    }

    if name == "__CFConstantStringClassReference" {
        return Some(std::ptr::addr_of!(CF_CONSTANT_STRING_CLASS_REFERENCE_STUB) as usize);
    }

    // C++ RTTI / vtable / type-name globals
    if name.starts_with("_ZTV")
        || name.starts_with("_ZTI")
        || name.starts_with("_ZTS")
        || name.starts_with("__ZTI")
    {
        return Some(dynamic_stub_data_ptr());
    }

    // Common data globals in libc++
    if name == "_ZNSt6__ndk14coutE"
        || name.ends_with("generic_categoryEv")
        || name.ends_with("system_categoryEv")
    {
        return Some(dynamic_stub_data_ptr());
    }

    // Constructors / destructors: return input object pointer when possible.
    if name.contains("C1E")
        || name.contains("C2E")
        || name.ends_with("C1Ev")
        || name.ends_with("C2Ev")
    {
        return Some(dynamic_stub_ctor as usize);
    }
    if name.contains("D0E")
        || name.contains("D1E")
        || name.contains("D2E")
        || name.ends_with("D0Ev")
        || name.ends_with("D1Ev")
        || name.ends_with("D2Ev")
    {
        return Some(dynamic_stub_noop as usize);
    }

    // Avoid waits blocking bootstrap forever.
    if name.starts_with("_ZN13mediaplatform9Semaphore4wait") {
        return Some(dynamic_stub_true as usize);
    }
    if name.starts_with("_ZN13mediaplatform9Semaphore6signal") {
        return Some(dynamic_stub_noop as usize);
    }

    // Common mediaplatform factories returning shared_ptr-style objects.
    if name.starts_with("_ZN13mediaplatform9WorkQueue13makeWorkQueue")
        || name.starts_with("_ZN13mediaplatform9WorkQueue15sharedWorkQueue")
        || name.starts_with("_ZN13mediaplatform9WorkQueue22defaultConcurrentQueue")
        || name.starts_with("_ZN13mediaplatform11HTTPRequest18requestWithMessage")
        || name.starts_with("_ZN13mediaplatform33CryptoDataFromBase64EncodedString")
    {
        return Some(dynamic_stub_shared_ptr_zero as usize);
    }
    if name.starts_with("_ZN13mediaplatform12Base64Encode") {
        return Some(dynamic_stub_ptr_out_zero as usize);
    }

    // Catch-all for unresolved NDK and mediaplatform functions.
    if name.starts_with("_ZNSt6__ndk1")
        || name.starts_with("_ZNKSt6__ndk1")
        || name.starts_with("_ZN13mediaplatform")
        || name.starts_with("_ZNK13mediaplatform")
        || name.starts_with("_ZTv0_n")
        || name.starts_with("_ZThn")
    {
        return Some(dynamic_stub_zero as usize);
    }

    None
}

fn dynamic_stub_data_ptr() -> usize {
    std::ptr::addr_of!(DYNAMIC_STUB_STORAGE) as usize
}

fn resolve_process_symbol(name: &str) -> Option<usize> {
    let c_name = CString::new(name).ok()?;
    unsafe {
        let addr = libc::dlsym(libc::RTLD_DEFAULT, c_name.as_ptr());
        if addr.is_null() {
            None
        } else {
            Some(addr as usize)
        }
    }
}

fn insert_process_symbol_or_stub(hooks: &mut HashMap<String, usize>, name: &str, stub: usize) {
    let addr = resolve_process_symbol(name).unwrap_or(stub);
    hooks.insert(name.to_string(), addr);
}

fn hook_trace_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("XAS_HOOK_TRACE")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    })
}

fn hook_trace(message: &str) {
    if hook_trace_enabled() {
        eprintln!("[hook] {message}");
    }
}

/// Custom pthread_once for Android compatibility.
/// Android's pthread_once_t is a 4-byte int (0=pending, 1=running, 2=done),
/// while macOS expects an 8-byte struct with different alignment requirements.
/// The macOS pthread_once uses `ldapr x8, [x20]` which requires 8-byte alignment,
/// but Android's 4-byte once_t may only be 4-byte aligned -> EXC_BAD_ACCESS.
extern "C" fn android_pthread_once(once_control: *mut i32, init_routine: extern "C" fn()) -> i32 {
    use std::sync::atomic::{AtomicI32, Ordering};
    if once_control.is_null() {
        return libc::EINVAL;
    }
    // Safety: Android pthread_once_t is a plain int; we treat it as AtomicI32.
    let atom = unsafe { &*(once_control as *const AtomicI32) };

    // Fast path: already done
    if atom.load(Ordering::Acquire) == 2 {
        return 0;
    }

    // Try to claim the init slot (0 -> 1)
    match atom.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => {
            // We won the race - run the init routine
            init_routine();
            atom.store(2, Ordering::Release);
            0
        }
        Err(2) => {
            // Another thread already completed
            0
        }
        Err(_) => {
            // Another thread is running init (state==1); spin until done
            while atom.load(Ordering::Acquire) != 2 {
                std::hint::spin_loop();
            }
            0
        }
    }
}

extern "C" fn dynamic_stub_noop() {}

extern "C" fn dynamic_stub_zero() -> usize {
    0
}

extern "C" fn dynamic_stub_true() -> i32 {
    1
}

extern "C" fn dynamic_stub_ctor(this: *mut c_void) -> *mut c_void {
    this
}

extern "C" fn dynamic_stub_shared_ptr_zero() -> usize {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let out: *mut usize;
        core::arch::asm!(
            "mov x9, x8",
            lateout("x9") out,
            options(nostack, preserves_flags),
        );
        if !out.is_null() {
            *out = 0;
            *out.add(1) = 0;
        }
    }

    #[cfg(target_arch = "x86_64")]
    unsafe {
        let out: *mut usize;
        core::arch::asm!(
            "mov rax, rdi",
            lateout("rax") out,
            options(nostack, preserves_flags),
        );
        if !out.is_null() {
            *out = 0;
            *out.add(1) = 0;
        }
    }

    0
}

extern "C" fn dynamic_stub_ptr_out_zero() -> usize {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let out: *mut usize;
        core::arch::asm!(
            "mov x9, x8",
            lateout("x9") out,
            options(nostack, preserves_flags),
        );
        if !out.is_null() {
            *out = 0;
        }
    }

    #[cfg(target_arch = "x86_64")]
    unsafe {
        let out: *mut usize;
        core::arch::asm!(
            "mov rax, rdi",
            lateout("rax") out,
            options(nostack, preserves_flags),
        );
        if !out.is_null() {
            *out = 0;
        }
    }

    0
}

#[derive(Clone, Copy)]
enum CfStubKind {
    Ptr,
    I32,
    I64,
    F64,
    Void,
    Retain,
    Range,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CFRangeStub {
    location: isize,
    length: isize,
}

const COREFOUNDATION_SYMBOLS: &[(&str, CfStubKind)] = &[
    ("CFAbsoluteTimeGetCurrent", CfStubKind::F64),
    ("CFArrayApplyFunction", CfStubKind::Void),
    ("CFArrayCreate", CfStubKind::Ptr),
    ("CFArrayGetCount", CfStubKind::I64),
    ("CFArrayGetTypeID", CfStubKind::I64),
    ("CFArrayGetValueAtIndex", CfStubKind::Ptr),
    ("CFArrayGetValues", CfStubKind::Void),
    ("CFBooleanGetTypeID", CfStubKind::I64),
    ("CFBooleanGetValue", CfStubKind::I32),
    ("CFCharacterSetGetPredefined", CfStubKind::Ptr),
    ("CFDataAppendBytes", CfStubKind::Void),
    ("CFDataCreate", CfStubKind::Ptr),
    ("CFDataCreateMutable", CfStubKind::Ptr),
    ("CFDataCreateWithBytesNoCopy", CfStubKind::Ptr),
    ("CFDataGetBytePtr", CfStubKind::Ptr),
    ("CFDataGetBytes", CfStubKind::Void),
    ("CFDataGetLength", CfStubKind::I64),
    ("CFDataGetTypeID", CfStubKind::I64),
    ("CFDictionaryApplyFunction", CfStubKind::Void),
    ("CFDictionaryContainsKey", CfStubKind::I32),
    ("CFDictionaryCreate", CfStubKind::Ptr),
    ("CFDictionaryCreateCopy", CfStubKind::Ptr),
    ("CFDictionaryCreateMutable", CfStubKind::Ptr),
    ("CFDictionaryCreateMutableCopy", CfStubKind::Ptr),
    ("CFDictionaryGetCount", CfStubKind::I64),
    ("CFDictionaryGetKeysAndValues", CfStubKind::Void),
    ("CFDictionaryGetTypeID", CfStubKind::I64),
    ("CFDictionaryGetValue", CfStubKind::Ptr),
    ("CFDictionaryRemoveValue", CfStubKind::Void),
    ("CFDictionarySetValue", CfStubKind::Void),
    ("CFEqual", CfStubKind::I32),
    ("CFGetTypeID", CfStubKind::I64),
    ("CFGregorianDateGetAbsoluteTime", CfStubKind::F64),
    ("CFGregorianDateIsValid", CfStubKind::I32),
    ("CFLocaleCreate", CfStubKind::Ptr),
    ("CFLocaleGetValue", CfStubKind::Ptr),
    ("CFNullGetTypeID", CfStubKind::I64),
    ("CFNumberCreate", CfStubKind::Ptr),
    ("CFNumberGetTypeID", CfStubKind::I64),
    ("CFNumberGetValue", CfStubKind::I32),
    ("CFPropertyListCreateData", CfStubKind::Ptr),
    ("CFPropertyListCreateWithData", CfStubKind::Ptr),
    ("CFRelease", CfStubKind::Void),
    ("CFRetain", CfStubKind::Retain),
    ("CFSetAddValue", CfStubKind::Void),
    ("CFSetApplyFunction", CfStubKind::Void),
    ("CFSetContainsValue", CfStubKind::I32),
    ("CFSetCreateMutable", CfStubKind::Ptr),
    ("CFSetCreateMutableCopy", CfStubKind::Ptr),
    ("CFStringAppend", CfStubKind::Void),
    ("CFStringCompare", CfStubKind::I32),
    ("CFStringCreateMutable", CfStubKind::Ptr),
    ("CFStringCreateMutableCopy", CfStubKind::Ptr),
    ("CFStringCreateWithBytes", CfStubKind::Ptr),
    ("CFStringCreateWithBytesNoCopy", CfStubKind::Ptr),
    ("CFStringCreateWithCString", CfStubKind::Ptr),
    ("CFStringCreateWithSubstring", CfStubKind::Ptr),
    ("CFStringFind", CfStubKind::Range),
    ("CFStringGetBytes", CfStubKind::I64),
    ("CFStringGetCString", CfStubKind::I32),
    ("CFStringGetCStringPtr", CfStubKind::Ptr),
    ("CFStringGetCharacters", CfStubKind::Void),
    ("CFStringGetCharactersPtr", CfStubKind::Ptr),
    ("CFStringGetDoubleValue", CfStubKind::F64),
    ("CFStringGetLength", CfStubKind::I64),
    ("CFStringGetMaximumSizeForEncoding", CfStubKind::I64),
    ("CFStringGetTypeID", CfStubKind::I64),
    ("CFStringHasPrefix", CfStubKind::I32),
    ("CFStringHasSuffix", CfStubKind::I32),
    ("CFStringInsert", CfStubKind::Void),
    ("CFTimeZoneCopyDefault", CfStubKind::Ptr),
    ("CFTimeZoneCreateWithTimeIntervalFromGMT", CfStubKind::Ptr),
    ("CFTimeZoneGetSecondsFromGMT", CfStubKind::F64),
    ("CFURLCopyHostName", CfStubKind::Ptr),
    ("CFURLCopyLastPathComponent", CfStubKind::Ptr),
    ("CFURLCopyPath", CfStubKind::Ptr),
    ("CFURLCopyQueryString", CfStubKind::Ptr),
    ("CFURLCopyScheme", CfStubKind::Ptr),
    ("CFURLCreateStringByAddingPercentEscapes", CfStubKind::Ptr),
    (
        "CFURLCreateStringByReplacingPercentEscapes",
        CfStubKind::Ptr,
    ),
    ("CFURLCreateWithString", CfStubKind::Ptr),
];

const COREFOUNDATION_CONSTANTS: &[&str] = &[
    "kCFAllocatorDefault",
    "kCFAllocatorNull",
    "kCFBooleanTrue",
    "kCFBooleanFalse",
    "kCFNull",
    "kCFTypeDictionaryKeyCallBacks",
    "kCFTypeDictionaryValueCallBacks",
    "kCFTypeArrayCallBacks",
    "kCFTypeSetCallBacks",
    "kCFAbsoluteTimeIntervalSince1970",
    "kCFLocaleLanguageCode",
];

fn register_corefoundation_hooks(hooks: &mut HashMap<String, usize>, mode: CoreFoundationMode) {
    let mut native_count = 0usize;
    let mut stub_count = 0usize;
    let mut native_const_count = 0usize;
    let mut stub_const_count = 0usize;

    match mode {
        CoreFoundationMode::Stub => {
            for (name, kind) in COREFOUNDATION_SYMBOLS {
                hooks.insert((*name).to_string(), corefoundation_stub_addr(*kind));
                stub_count += 1;
            }
            for name in COREFOUNDATION_CONSTANTS {
                hooks.insert((*name).to_string(), dynamic_stub_data_ptr());
                stub_const_count += 1;
            }
            hooks.insert(
                "__CFConstantStringClassReference".to_string(),
                std::ptr::addr_of!(CF_CONSTANT_STRING_CLASS_REFERENCE_STUB) as usize,
            );
        }
        CoreFoundationMode::Auto => {
            // Do not register CF hooks in auto mode.
            // This keeps symbol resolution on the real loaded Android libraries first.
        }
        CoreFoundationMode::Native => {
            #[cfg(target_os = "macos")]
            {
                for (name, _kind) in COREFOUNDATION_SYMBOLS {
                    if let Some(native) = resolve_corefoundation_symbol(name) {
                        hooks.insert((*name).to_string(), native);
                        native_count += 1;
                    }
                }
                for name in COREFOUNDATION_CONSTANTS {
                    if let Some(native) = resolve_corefoundation_symbol(name) {
                        hooks.insert((*name).to_string(), native);
                        native_const_count += 1;
                    }
                }
            }
        }
    }

    let debug_enabled = std::env::var("XAS_CF_DEBUG")
        .ok()
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if debug_enabled {
        eprintln!(
            "CoreFoundation hooks configured: mode={mode:?}, native_fn={native_count}, stub_fn={stub_count}, native_const={native_const_count}, stub_const={stub_const_count}"
        );
    }
}

#[cfg(target_os = "macos")]
fn resolve_corefoundation_symbol(symbol: &str) -> Option<usize> {
    let handle = corefoundation_handle()?;
    let c_name = CString::new(symbol).ok()?;
    let addr = unsafe { libc::dlsym(handle, c_name.as_ptr()) };
    if addr.is_null() {
        None
    } else {
        Some(addr as usize)
    }
}

#[cfg(target_os = "macos")]
fn corefoundation_handle() -> Option<*mut c_void> {
    static HANDLE: OnceLock<usize> = OnceLock::new();
    let raw = *HANDLE.get_or_init(|| unsafe {
        let path =
            CString::new("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
                .expect("valid cstring");
        let handle = libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL);
        if handle.is_null() { 0 } else { handle as usize }
    });
    if raw == 0 {
        None
    } else {
        Some(raw as *mut c_void)
    }
}

fn corefoundation_stub_addr(kind: CfStubKind) -> usize {
    match kind {
        CfStubKind::Ptr => cf_stub_ptr as usize,
        CfStubKind::I32 => cf_stub_i32 as usize,
        CfStubKind::I64 => cf_stub_i64 as usize,
        CfStubKind::F64 => cf_stub_f64 as usize,
        CfStubKind::Void => cf_stub_void as usize,
        CfStubKind::Retain => cf_stub_retain as usize,
        CfStubKind::Range => cf_stub_range as usize,
    }
}

extern "C" fn cf_stub_ptr() -> *const c_void {
    std::ptr::null()
}

extern "C" fn cf_stub_i32() -> i32 {
    0
}

extern "C" fn cf_stub_i64() -> i64 {
    0
}

extern "C" fn cf_stub_f64() -> f64 {
    0.0
}

extern "C" fn cf_stub_void() {}

extern "C" fn cf_stub_retain(value: *const c_void) -> *const c_void {
    value
}

extern "C" fn cf_stub_range() -> CFRangeStub {
    CFRangeStub {
        location: -1,
        length: 0,
    }
}

extern "C" fn mediaplatform_data_ctor_default_stub(this: *mut c_void) -> *mut c_void {
    if this.is_null() {
        return this;
    }
    unsafe {
        let obj = this as *mut MpDataStub;
        *obj = MpDataStub {
            tag: MP_DATA_TAG,
            len: 0,
            cap: 0,
            ptr: std::ptr::null_mut(),
        };
    }
    this
}

extern "C" fn mediaplatform_data_ctor_from_bytes_stub(
    this: *mut c_void,
    src: *const c_void,
    len: usize,
    _copy: bool,
) -> *mut c_void {
    if this.is_null() {
        return this;
    }
    unsafe {
        let obj = this as *mut MpDataStub;
        let mut out_ptr = std::ptr::null_mut();
        if !src.is_null() && len > 0 {
            out_ptr = libc::malloc(len) as *mut u8;
            if !out_ptr.is_null() {
                std::ptr::copy_nonoverlapping(src as *const u8, out_ptr, len);
            }
        }
        *obj = MpDataStub {
            tag: MP_DATA_TAG,
            len: if out_ptr.is_null() { 0 } else { len },
            cap: if out_ptr.is_null() { 0 } else { len },
            ptr: out_ptr,
        };
    }
    this
}

extern "C" fn mediaplatform_data_dtor_stub(this: *mut c_void) {
    if this.is_null() {
        return;
    }
    unsafe {
        let obj = this as *mut MpDataStub;
        if (*obj).tag == MP_DATA_TAG && !(*obj).ptr.is_null() {
            libc::free((*obj).ptr as *mut c_void);
        }
        *obj = MpDataStub {
            tag: 0,
            len: 0,
            cap: 0,
            ptr: std::ptr::null_mut(),
        };
    }
}

unsafe fn mp_data_extract(this: *const c_void) -> (*const u8, usize) {
    if this.is_null() {
        return (std::ptr::null(), 0);
    }

    let obj = this as *const MpDataStub;
    if (*obj).tag == MP_DATA_TAG {
        return ((*obj).ptr as *const u8, (*obj).len);
    }

    // Best-effort fallback for non-stub mediaplatform::Data layouts observed in traces:
    // [0x08] length, [0x10] length/capacity, [0x18] bytes pointer
    let q = this as *const usize;
    let len0 = *q.add(1);
    let len1 = *q.add(2);
    let ptr = *q.add(3) as *const u8;
    let len = if len0 == len1 || len1 == 0 {
        len0
    } else {
        len0.min(len1)
    };
    if ptr.is_null() {
        (std::ptr::null(), 0)
    } else {
        (ptr, len.min(1024 * 1024))
    }
}

extern "C" fn mediaplatform_data_bytes_stub(this: *const c_void) -> *const c_void {
    unsafe {
        let (ptr, _len) = mp_data_extract(this);
        hook_trace("mediaplatform::Data::bytes");
        ptr as *const c_void
    }
}

extern "C" fn mediaplatform_data_length_stub(this: *const c_void) -> usize {
    unsafe {
        let (_ptr, len) = mp_data_extract(this);
        hook_trace("mediaplatform::Data::length");
        len
    }
}

unsafe fn cf_data_extract(data: *const c_void) -> (*const u8, usize) {
    if data.is_null() {
        return (std::ptr::null(), 0);
    }

    let raw = data as *const u8;
    let tag = std::ptr::read_unaligned(raw as *const u64);
    if tag != CF_DATA_TAG {
        return (std::ptr::null(), 0);
    }

    let len = std::ptr::read_unaligned(raw.add(8) as *const usize);
    let ptr = std::ptr::read_unaligned(raw.add(16) as *const *mut u8);
    (ptr as *const u8, len)
}

unsafe fn cf_string_extract(string: *const c_void) -> Option<(*const u8, usize)> {
    if string.is_null() {
        return None;
    }

    let raw = string as *const u8;
    let tag = std::ptr::read_unaligned(raw as *const u64);
    if tag != CF_STRING_TAG {
        return None;
    }

    let len = std::ptr::read_unaligned(raw.add(8) as *const usize);
    let ptr = std::ptr::read_unaligned(raw.add(16) as *const *mut u8);
    Some((ptr as *const u8, len))
}

fn base64_encode_bytes(input: &[u8]) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if input.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0usize;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 0x3f) as usize]);
        out.push(TABLE[((n >> 12) & 0x3f) as usize]);
        out.push(TABLE[((n >> 6) & 0x3f) as usize]);
        out.push(TABLE[(n & 0x3f) as usize]);
        i += 3;
    }

    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        out.push(TABLE[((n >> 18) & 0x3f) as usize]);
        out.push(TABLE[((n >> 12) & 0x3f) as usize]);
        out.push(b'=');
        out.push(b'=');
    } else if rem == 2 {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out.push(TABLE[((n >> 18) & 0x3f) as usize]);
        out.push(TABLE[((n >> 12) & 0x3f) as usize]);
        out.push(TABLE[((n >> 6) & 0x3f) as usize]);
        out.push(b'=');
    }

    out
}

unsafe fn cf_string_from_bytes(bytes: &[u8]) -> *mut c_void {
    let obj = libc::malloc(std::mem::size_of::<CfStringStub>()) as *mut CfStringStub;
    if obj.is_null() {
        return std::ptr::null_mut();
    }

    let ptr = if !bytes.is_empty() {
        let ptr = libc::malloc(bytes.len() + 1) as *mut u8;
        if ptr.is_null() {
            libc::free(obj as *mut c_void);
            return std::ptr::null_mut();
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
        *ptr.add(bytes.len()) = 0;
        ptr
    } else {
        let ptr = libc::malloc(1) as *mut u8;
        if !ptr.is_null() {
            *ptr = 0;
        }
        ptr
    };

    *obj = CfStringStub {
        tag: CF_STRING_TAG,
        len: bytes.len(),
        ptr,
    };
    obj as *mut c_void
}

extern "C" fn mediaplatform_base64_encode_stub(cf_data: *const c_void) -> usize {
    hook_trace("mediaplatform::Base64Encode");
    let encoded = unsafe {
        let (ptr, len) = cf_data_extract(cf_data);
        if ptr.is_null() || len == 0 {
            Vec::new()
        } else {
            base64_encode_bytes(std::slice::from_raw_parts(ptr, len))
        }
    };
    let cf_string = unsafe { cf_string_from_bytes(&encoded) as usize };

    #[cfg(target_arch = "aarch64")]
    unsafe {
        let out: *mut usize;
        core::arch::asm!(
            "mov x9, x8",
            lateout("x9") out,
            options(nostack, preserves_flags),
        );
        if !out.is_null() {
            *out = cf_string;
            *out.add(1) = 0;
        }
    }

    #[cfg(target_arch = "x86_64")]
    unsafe {
        let out: *mut usize;
        core::arch::asm!(
            "mov rax, rdi",
            lateout("rax") out,
            options(nostack, preserves_flags),
        );
        if !out.is_null() {
            *out = cf_string;
            *out.add(1) = 0;
        }
    }

    0
}

extern "C" fn cf_data_create_with_bytes_no_copy_stub(
    _allocator: *const c_void,
    bytes: *const u8,
    length: isize,
    _bytes_deallocator: *const c_void,
) -> *mut c_void {
    hook_trace("CFDataCreateWithBytesNoCopy");
    if length < 0 {
        return std::ptr::null_mut();
    }

    unsafe {
        let obj = libc::malloc(std::mem::size_of::<CfDataStub>()) as *mut CfDataStub;
        if obj.is_null() {
            return std::ptr::null_mut();
        }

        let len = length as usize;
        let mut ptr = std::ptr::null_mut();
        if len > 0 && !bytes.is_null() {
            ptr = libc::malloc(len) as *mut u8;
            if !ptr.is_null() {
                std::ptr::copy_nonoverlapping(bytes, ptr, len);
            }
        }

        *obj = CfDataStub {
            tag: CF_DATA_TAG,
            len: if ptr.is_null() { 0 } else { len },
            ptr,
        };
        obj as *mut c_void
    }
}

extern "C" fn cf_data_get_byte_ptr_stub(data: *const c_void) -> *const u8 {
    hook_trace("CFDataGetBytePtr");
    unsafe {
        let (ptr, _len) = cf_data_extract(data);
        ptr
    }
}

extern "C" fn cf_data_get_length_stub(data: *const c_void) -> isize {
    hook_trace("CFDataGetLength");
    unsafe {
        let (_ptr, len) = cf_data_extract(data);
        len as isize
    }
}

extern "C" fn cf_string_get_length_stub(string: *const c_void) -> isize {
    hook_trace("CFStringGetLength");
    unsafe {
        cf_string_extract(string)
            .map(|(_ptr, len)| len as isize)
            .unwrap_or(0)
    }
}

extern "C" fn cf_string_get_maximum_size_for_encoding_stub(length: isize, _encoding: u32) -> isize {
    hook_trace("CFStringGetMaximumSizeForEncoding");
    if length <= 0 {
        0
    } else {
        length.saturating_mul(4)
    }
}

extern "C" fn cf_string_get_cstring_stub(
    string: *const c_void,
    buffer: *mut c_char,
    buffer_size: isize,
    _encoding: u32,
) -> i32 {
    hook_trace("CFStringGetCString");
    if string.is_null() || buffer.is_null() || buffer_size <= 0 {
        return 0;
    }
    unsafe {
        let Some((ptr, len)) = cf_string_extract(string) else {
            *buffer = 0;
            return 0;
        };
        if ptr.is_null() {
            *buffer = 0;
            return 0;
        }

        let cap = buffer_size as usize;
        if cap == 0 {
            return 0;
        }
        let copy_len = len.min(cap.saturating_sub(1));
        std::ptr::copy_nonoverlapping(ptr as *const c_char, buffer, copy_len);
        *buffer.add(copy_len) = 0;
        if copy_len == len { 1 } else { 0 }
    }
}

extern "C" fn cf_retain_stub(value: *const c_void) -> *const c_void {
    hook_trace("CFRetain");
    value
}

extern "C" fn cf_release_stub(value: *const c_void) {
    hook_trace("CFRelease");
    if value.is_null() {
        return;
    }
    unsafe {
        let tag = std::ptr::read_unaligned(value as *const u64);
        if tag == CF_DATA_TAG || tag == CF_STRING_TAG {
            let raw = value as *mut u8;
            let ptr = std::ptr::read_unaligned(raw.add(16) as *const *mut u8);
            if !ptr.is_null() {
                libc::free(ptr as *mut c_void);
            }
            libc::free(value as *mut c_void);
        }
    }
}

static CF_CONSTANT_STRING_CLASS_REFERENCE_STUB: usize = 0;

fn corefoundation_symbol_kind(name: &str) -> Option<CfStubKind> {
    COREFOUNDATION_SYMBOLS
        .iter()
        .find_map(|(symbol, kind)| if *symbol == name { Some(*kind) } else { None })
}

fn is_corefoundation_constant(name: &str) -> bool {
    name.starts_with("kCF") || COREFOUNDATION_CONSTANTS.contains(&name)
}

#[repr(C)]
struct NdkStringAbi {
    raw: [u8; 24],
}

fn ndk_string_is_long(raw: &[u8; 24]) -> bool {
    raw[0] & 1 == 1
}

fn ndk_string_read_u64(raw: &[u8; 24], offset: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&raw[offset..offset + 8]);
    u64::from_le_bytes(buf)
}

fn ndk_string_write_u64(raw: &mut [u8; 24], offset: usize, value: u64) {
    raw[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

unsafe fn ndk_string_clear(this: *mut NdkStringAbi) {
    if this.is_null() {
        return;
    }
    if ndk_string_is_long(&(*this).raw) {
        let ptr = ndk_string_read_u64(&(*this).raw, 16) as usize as *mut c_void;
        if !ptr.is_null() {
            libc::free(ptr);
        }
    }
    (*this).raw = [0; 24];
}

unsafe fn ndk_string_set(this: *mut NdkStringAbi, bytes: &[u8]) {
    ndk_string_clear(this);
    let raw = &mut (*this).raw;

    if bytes.len() <= NDK_STRING_SHORT_MAX {
        raw[0] = ((bytes.len() as u8) << 1) & 0xfe;
        if !bytes.is_empty() {
            raw[1..1 + bytes.len()].copy_from_slice(bytes);
        }
        raw[1 + bytes.len()] = 0;
        return;
    }

    let alloc_len = bytes.len().saturating_add(1);
    let ptr = libc::malloc(alloc_len) as *mut u8;
    if ptr.is_null() {
        return;
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
    *ptr.add(bytes.len()) = 0;

    *raw = [0; 24];
    raw[0] = 1;
    ndk_string_write_u64(raw, 8, bytes.len() as u64);
    ndk_string_write_u64(raw, 16, ptr as usize as u64);
}

extern "C" fn ndk_string_assign(this: *mut NdkStringAbi, src: *const c_char) -> *mut NdkStringAbi {
    if this.is_null() {
        return this;
    }
    let bytes = if src.is_null() {
        &[][..]
    } else {
        unsafe { CStr::from_ptr(src) }.to_bytes()
    };
    unsafe {
        ndk_string_set(this, bytes);
    }
    this
}

extern "C" fn ndk_string_dtor(this: *mut NdkStringAbi) {
    unsafe {
        ndk_string_clear(this);
    }
}

// errno support (thread-local for correctness)
thread_local! {
    static ERRNO_VALUE: std::cell::Cell<i32> = const { std::cell::Cell::new(0) };
}

extern "C" fn errno_location() -> *mut i32 {
    ERRNO_VALUE.with(|cell| cell.as_ptr())
}

#[inline]
fn set_errno(code: i32) {
    ERRNO_VALUE.with(|cell| cell.set(code));
}

extern "C" fn strlen_chk_stub(s: *const c_char, _slen: usize) -> usize {
    if s.is_null() {
        return 0;
    }
    unsafe { libc::strlen(s) }
}

extern "C" fn strchr_chk_stub(s: *const c_char, c: i32, _slen: usize) -> *mut c_char {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    unsafe { libc::strchr(s, c) as *mut c_char }
}

extern "C" fn strncpy_chk2_stub(
    dst: *mut c_char,
    src: *const c_char,
    n: usize,
    _dst_len: usize,
    _src_len: usize,
) -> *mut c_char {
    if dst.is_null() || src.is_null() {
        return dst;
    }
    unsafe { libc::strncpy(dst, src, n) }
}

extern "C" fn memrchr_stub(s: *const c_void, c: i32, n: usize) -> *mut c_void {
    if s.is_null() || n == 0 {
        return std::ptr::null_mut();
    }
    let needle = c as u8;
    let bytes = unsafe { std::slice::from_raw_parts(s as *const u8, n) };
    for idx in (0..n).rev() {
        if bytes[idx] == needle {
            return unsafe { (s as *const u8).add(idx) as *mut c_void };
        }
    }
    std::ptr::null_mut()
}

extern "C" fn read_chk_stub(fd: i32, buf: *mut c_void, nbytes: usize, buflen: usize) -> isize {
    if nbytes > buflen {
        set_errno(libc::EOVERFLOW);
        return -1;
    }
    unsafe { libc::read(fd, buf, nbytes) }
}

extern "C" fn open_2_stub(path: *const c_char, flags: i32) -> i32 {
    unsafe { libc::open(path, flags) }
}

extern "C" fn fd_set_chk_stub(fd: i32, set: *mut c_void, set_bytes: usize) {
    unsafe {
        fd_bit_op(fd, set as *mut libc::c_long, set_bytes, true);
    }
}

extern "C" fn fd_clr_chk_stub(fd: i32, set: *mut c_void, set_bytes: usize) {
    unsafe {
        fd_bit_op(fd, set as *mut libc::c_long, set_bytes, false);
    }
}

extern "C" fn fd_isset_chk_stub(fd: i32, set: *const c_void, set_bytes: usize) -> i32 {
    if fd < 0 || set.is_null() {
        return 0;
    }
    let bits_per_word = std::mem::size_of::<libc::c_long>() * 8;
    let fd_u = fd as usize;
    let word_idx = fd_u / bits_per_word;
    let bit_idx = fd_u % bits_per_word;
    let word_count = set_bytes / std::mem::size_of::<libc::c_long>();
    if word_idx >= word_count {
        set_errno(libc::EINVAL);
        return 0;
    }
    unsafe {
        let words = set as *const libc::c_long;
        let word = *words.add(word_idx) as u64;
        ((word >> bit_idx) & 1) as i32
    }
}

unsafe fn fd_bit_op(fd: i32, set: *mut libc::c_long, set_bytes: usize, enable: bool) {
    if fd < 0 || set.is_null() {
        return;
    }
    let bits_per_word = std::mem::size_of::<libc::c_long>() * 8;
    let fd_u = fd as usize;
    let word_idx = fd_u / bits_per_word;
    let bit_idx = fd_u % bits_per_word;
    let word_count = set_bytes / std::mem::size_of::<libc::c_long>();
    if word_idx >= word_count {
        set_errno(libc::EINVAL);
        return;
    }

    let word = set.add(word_idx);
    let mask = (1u64 << bit_idx) as libc::c_long;
    if enable {
        *word |= mask;
    } else {
        *word &= !mask;
    }
}

extern "C" fn gettid_stub() -> libc::pid_t {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe {
        libc::syscall(libc::SYS_gettid as libc::c_long) as libc::pid_t
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    unsafe {
        libc::getpid()
    }
}

extern "C" fn mediaplatform_debug_log_disabled(_priority: i32) -> bool {
    false
}

extern "C" fn posix_fadvise_stub(
    _fd: i32,
    _offset: libc::off_t,
    _len: libc::off_t,
    _advice: i32,
) -> i32 {
    0
}

extern "C" fn mremap_stub(
    _old_address: *mut c_void,
    _old_size: usize,
    _new_size: usize,
    _flags: i32,
) -> *mut c_void {
    set_errno(libc::ENOSYS);
    libc::MAP_FAILED
}

extern "C" fn eventfd_stub(_initval: u32, _flags: i32) -> i32 {
    set_errno(libc::ENOSYS);
    -1
}

extern "C" fn eventfd_read_stub(_fd: i32, value: *mut u64) -> i32 {
    if !value.is_null() {
        unsafe {
            *value = 0;
        }
    }
    set_errno(libc::ENOSYS);
    -1
}

extern "C" fn eventfd_write_stub(_fd: i32, _value: u64) -> i32 {
    set_errno(libc::ENOSYS);
    -1
}

extern "C" fn epoll_create_stub(_size: i32) -> i32 {
    set_errno(libc::ENOSYS);
    -1
}

extern "C" fn epoll_ctl_stub(_epfd: i32, _op: i32, _fd: i32, _event: *mut c_void) -> i32 {
    set_errno(libc::ENOSYS);
    -1
}

extern "C" fn epoll_wait_stub(
    _epfd: i32,
    _events: *mut c_void,
    _maxevents: i32,
    _timeout: i32,
) -> i32 {
    set_errno(libc::ENOSYS);
    -1
}

extern "C" fn timerfd_create_stub(_clockid: i32, _flags: i32) -> i32 {
    set_errno(libc::ENOSYS);
    -1
}

extern "C" fn timerfd_settime_stub(
    _fd: i32,
    _flags: i32,
    _new_value: *const c_void,
    _old_value: *mut c_void,
) -> i32 {
    set_errno(libc::ENOSYS);
    -1
}

extern "C" fn signalfd_stub(_fd: i32, _mask: *const c_void, _flags: i32) -> i32 {
    set_errno(libc::ENOSYS);
    -1
}

extern "C" fn sem_timedwait_stub(
    _sem: *mut libc::sem_t,
    _abs_timeout: *const libc::timespec,
) -> i32 {
    set_errno(libc::ETIMEDOUT);
    -1
}

// Random number generation
extern "C" fn arc4random() -> u32 {
    rand::random()
}

extern "C" fn arc4random_buf(buf: *mut u8, len: usize) {
    if buf.is_null() || len == 0 {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    rand::rng().fill(slice);
}

// Android system property stub
extern "C" fn system_property_get(_name: *const c_char, value: *mut c_char) -> i32 {
    if value.is_null() {
        return 0;
    }
    // Return empty property
    unsafe {
        *value = 0;
    }
    0
}

// Android logging stubs - non-variadic versions that just return 0
extern "C" fn android_log_print_stub(_prio: i32, _tag: *const c_char, _fmt: *const c_char) -> i32 {
    0
}

extern "C" fn android_log_write(_prio: i32, _tag: *const c_char, _text: *const c_char) -> i32 {
    0
}

extern "C" fn android_log_vprint(
    _prio: i32,
    _tag: *const c_char,
    _fmt: *const c_char,
    _ap: *mut libc::c_void,
) -> i32 {
    0
}

extern "C" fn pthread_mutex_init_stub(
    _mutex: *mut libc::pthread_mutex_t,
    _attr: *const libc::pthread_mutexattr_t,
) -> i32 {
    0
}

extern "C" fn pthread_mutex_destroy_stub(_mutex: *mut libc::pthread_mutex_t) -> i32 {
    0
}

extern "C" fn pthread_mutex_lock_stub(_mutex: *mut libc::pthread_mutex_t) -> i32 {
    0
}

extern "C" fn pthread_mutex_unlock_stub(_mutex: *mut libc::pthread_mutex_t) -> i32 {
    0
}

extern "C" fn pthread_mutex_trylock_stub(_mutex: *mut libc::pthread_mutex_t) -> i32 {
    0
}

// C++ runtime stubs
extern "C" fn cxa_atexit(
    _func: *mut libc::c_void,
    _arg: *mut libc::c_void,
    _dso_handle: *mut libc::c_void,
) -> i32 {
    0
}

extern "C" fn cxa_finalize(_dso_handle: *mut libc::c_void) {}

extern "C" fn cxa_thread_atexit_impl(
    _func: *mut libc::c_void,
    _arg: *mut libc::c_void,
    _dso_handle: *mut libc::c_void,
) -> i32 {
    0
}

// dl* hooks - first resolve against preloaded in-process Android SO handles.
extern "C" fn hook_dlopen(filename: *const c_char, flags: i32) -> *mut libc::c_void {
    let path = if filename.is_null() {
        ""
    } else {
        unsafe { CStr::from_ptr(filename) }.to_str().unwrap_or("")
    };
    if !path.is_empty()
        && let Some(handle) = lookup_registered_library_handle(path)
    {
        let init_ok = ensure_registered_library_initialized(handle);
        if hook_trace_enabled() {
            eprintln!("[hook] dlopen(preloaded) {path} => {handle:p} (init_ok={init_ok})");
        }
        return handle;
    }
    unsafe { libc::dlopen(filename, flags) }
}

extern "C" fn hook_dlsym(handle: *mut libc::c_void, symbol: *const c_char) -> *mut libc::c_void {
    if symbol.is_null() {
        return std::ptr::null_mut();
    }

    let name = unsafe { CStr::from_ptr(symbol) }.to_str().unwrap_or("");
    if name.is_empty() {
        return std::ptr::null_mut();
    }

    // Match relocation behavior: hooks first.
    if let Some(addr) = GLOBAL_HOOKS.lock().unwrap().get(name).copied() {
        if hook_trace_enabled() {
            eprintln!("[hook] dlsym(hook) {name} => {addr:#x}");
        }
        return addr as *mut libc::c_void;
    }

    if let Some(addr) = lookup_symbol_in_registered_library(handle, name) {
        if hook_trace_enabled() {
            eprintln!("[hook] dlsym(preloaded) {name} => {addr:#x}");
        }
        return addr as *mut libc::c_void;
    }

    // For fake handles from preloaded SOs, do not forward invalid handles into libc dlsym.
    if is_registered_library_handle(handle) {
        return std::ptr::null_mut();
    }

    unsafe { libc::dlsym(handle, symbol) }
}

extern "C" fn hook_dlclose(handle: *mut libc::c_void) -> i32 {
    if is_registered_library_handle(handle) {
        if hook_trace_enabled() {
            eprintln!("[hook] dlclose(preloaded) {handle:p} => 0");
        }
        return 0;
    }
    unsafe { libc::dlclose(handle) }
}

extern "C" fn hook_dlerror() -> *mut c_char {
    unsafe { libc::dlerror() }
}

// Math function wrappers
extern "C" fn libm_sin(x: f64) -> f64 {
    x.sin()
}
extern "C" fn libm_cos(x: f64) -> f64 {
    x.cos()
}
extern "C" fn libm_tan(x: f64) -> f64 {
    x.tan()
}
extern "C" fn libm_sqrt(x: f64) -> f64 {
    x.sqrt()
}
extern "C" fn libm_pow(x: f64, y: f64) -> f64 {
    x.powf(y)
}
extern "C" fn libm_log(x: f64) -> f64 {
    x.ln()
}
extern "C" fn libm_exp(x: f64) -> f64 {
    x.exp()
}
extern "C" fn libm_floor(x: f64) -> f64 {
    x.floor()
}
extern "C" fn libm_ceil(x: f64) -> f64 {
    x.ceil()
}
extern "C" fn libm_fabs(x: f64) -> f64 {
    x.abs()
}
extern "C" fn sincos_stub(x: f64, sin_out: *mut f64, cos_out: *mut f64) {
    if !sin_out.is_null() {
        unsafe { *sin_out = x.sin() };
    }
    if !cos_out.is_null() {
        unsafe { *cos_out = x.cos() };
    }
}
extern "C" fn zlib_inflate_init_stub(
    _strm: *mut c_void,
    _version: *const c_char,
    _stream_size: i32,
) -> i32 {
    0
}
extern "C" fn zlib_inflate_init2_stub(
    _strm: *mut c_void,
    _window_bits: i32,
    _version: *const c_char,
    _stream_size: i32,
) -> i32 {
    0
}
extern "C" fn zlib_inflate_stub(_strm: *mut c_void, _flush: i32) -> i32 {
    0
}
extern "C" fn zlib_inflate_end_stub(_strm: *mut c_void) -> i32 {
    0
}
extern "C" fn zlib_version_stub() -> *const c_char {
    static VERSION: &[u8] = b"1.2.11\0";
    VERSION.as_ptr() as *const c_char
}
extern "C" fn zlib_deflate_init2_stub(
    _strm: *mut c_void,
    _level: i32,
    _method: i32,
    _window_bits: i32,
    _mem_level: i32,
    _strategy: i32,
    _version: *const c_char,
    _stream_size: i32,
) -> i32 {
    0
}
extern "C" fn zlib_deflate_stub(_strm: *mut c_void, _flush: i32) -> i32 {
    0
}
extern "C" fn zlib_deflate_end_stub(_strm: *mut c_void) -> i32 {
    0
}
extern "C" fn crc32_stub(crc: libc::c_ulong, _buf: *const u8, _len: libc::c_uint) -> libc::c_ulong {
    crc
}
extern "C" fn gzopen_stub(_path: *const c_char, _mode: *const c_char) -> *mut c_void {
    set_errno(libc::ENOSYS);
    std::ptr::null_mut()
}
extern "C" fn gzdopen_stub(_fd: i32, _mode: *const c_char) -> *mut c_void {
    set_errno(libc::ENOSYS);
    std::ptr::null_mut()
}
extern "C" fn gzread_stub(_file: *mut c_void, _buf: *mut c_void, _len: libc::c_uint) -> i32 {
    set_errno(libc::ENOSYS);
    -1
}
extern "C" fn gzwrite_stub(_file: *mut c_void, _buf: *const c_void, _len: libc::c_uint) -> i32 {
    set_errno(libc::ENOSYS);
    -1
}
extern "C" fn gzclose_stub(_file: *mut c_void) -> i32 {
    0
}
extern "C" fn gzdirect_stub(_file: *mut c_void) -> i32 {
    0
}

thread_local! {
    static H_ERRNO_VALUE: std::cell::Cell<i32> = const { std::cell::Cell::new(0) };
}

extern "C" fn get_h_errno_stub() -> *mut i32 {
    H_ERRNO_VALUE.with(|cell| cell.as_ptr())
}

extern "C" fn ctype_get_mb_cur_max_stub() -> usize {
    1
}

extern "C" fn android_set_abort_message_stub(_msg: *const c_char) {}

extern "C" fn malloc_usable_size_stub(_ptr: *const c_void) -> usize {
    0
}

extern "C" fn ppoll_stub(
    fds: *mut libc::pollfd,
    nfds: libc::nfds_t,
    timeout: *const libc::timespec,
    _sigmask: *const libc::sigset_t,
) -> i32 {
    let timeout_ms = if timeout.is_null() {
        -1
    } else {
        let t = unsafe { *timeout };
        let secs_ms = t.tv_sec.saturating_mul(1000);
        let nanos_ms = t.tv_nsec.saturating_div(1_000_000);
        secs_ms
            .saturating_add(nanos_ms)
            .clamp(i32::MIN as i64, i32::MAX as i64) as i32
    };
    unsafe { libc::poll(fds, nfds, timeout_ms) }
}

// Linux-specific stubs
extern "C" fn dl_iterate_phdr_stub(
    _callback: *mut libc::c_void,
    _data: *mut libc::c_void,
) -> libc::c_int {
    0 // Return 0 to indicate no more objects
}

extern "C" fn getauxval_stub(_type: libc::c_ulong) -> libc::c_ulong {
    0 // Return 0 for all auxiliary vector values
}

// C++ exception handling stubs
extern "C" fn cxa_begin_catch(_exception: *mut libc::c_void) -> *mut libc::c_void {
    std::ptr::null_mut()
}

extern "C" fn cxa_end_catch() {}

extern "C" fn cxa_allocate_exception(_size: usize) -> *mut libc::c_void {
    std::ptr::null_mut()
}

// C++ exceptions cannot unwind through these Rust hook frames. Abort instead of
// letting foreign unwinding corrupt host state.
extern "C" fn cxa_throw(
    _exception: *mut libc::c_void,
    _type: *mut libc::c_void,
    _destructor: *mut libc::c_void,
) {
    eprintln!("[hook] FATAL: __cxa_throw called - native C++ exception thrown, aborting");
    std::process::abort();
}

extern "C" fn cxa_rethrow() {
    eprintln!("[hook] FATAL: __cxa_rethrow called - native C++ exception rethrown, aborting");
    std::process::abort();
}

extern "C" fn gxx_personality_v0() -> i32 {
    0
}

extern "C" fn unwind_resume(_exception: *mut libc::c_void) {
    eprintln!("[hook] FATAL: _Unwind_Resume called - unhandled C++ exception, aborting");
    std::process::abort();
}

// C++ guard functions for static initialization
extern "C" fn cxa_guard_acquire(guard: *mut i64) -> i32 {
    unsafe {
        if *guard == 0 {
            *guard = 1;
            1 // Return 1 to indicate initialization should proceed
        } else {
            0 // Already initialized
        }
    }
}

extern "C" fn cxa_guard_release(_guard: *mut i64) {}

extern "C" fn cxa_guard_abort(_guard: *mut i64) {}

extern "C" fn cxa_pure_virtual() {
    eprintln!("Pure virtual function called!");
    std::process::abort();
}
