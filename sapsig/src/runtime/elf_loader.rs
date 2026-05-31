//! ELF loader for Android x86_64 shared libraries
#![allow(dead_code)]
#![allow(unsafe_op_in_unsafe_fn)]

use anyhow::{Context, Result, anyhow, bail};
use goblin::elf::{
    Elf,
    program_header::{PF_R, PF_W, PF_X, PT_LOAD},
    reloc::*,
    sym::STT_FUNC,
};
use std::ffi::c_void;

// AArch64 relocation types (not in goblin::elf::reloc)
const R_AARCH64_ABS64: u32 = 257;
const R_AARCH64_GLOB_DAT: u32 = 1025;
const R_AARCH64_JUMP_SLOT: u32 = 1026;
const R_AARCH64_RELATIVE: u32 = 1027;
const R_AARCH64_TLS_TPREL64: u32 = 1030;
const R_AARCH64_TLS_DTPREL64: u32 = 1028;
const R_AARCH64_TLS_DTPMOD64: u32 = 1029;
const R_AARCH64_IRELATIVE: u32 = 1032;
const DT_INIT: u64 = 12;
const DT_INIT_ARRAY: u64 = 25;
const DT_INIT_ARRAYSZ: u64 = 27;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::hooks::{GLOBAL_HOOKS, resolve_dynamic_symbol_fallback};

// -- W^X conflict page tracking (macOS 16KB pages) --
// On macOS ARM64, pages are 16KB but ELF segments use 4KB alignment.
// When an EXEC segment and a RW segment share a 16KB page, we can't satisfy
// both due to W^X policy. We track these "conflict pages" and use a SIGBUS
// signal handler to toggle between R+X and RW on demand.
#[cfg(target_os = "macos")]
mod wx_conflict {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::OnceLock;

    /// A page that needs both EXEC and WRITE at different times.
    #[derive(Clone, Copy)]
    pub struct ConflictPage {
        pub addr: usize,   // page-aligned virtual address
        pub size: usize,   // page size
        pub is_exec: bool, // current state: true=R+X, false=RW
    }

    /// Global registry of conflict pages, keyed by page address.
    fn registry() -> &'static Mutex<HashMap<usize, ConflictPage>> {
        static REG: OnceLock<Mutex<HashMap<usize, ConflictPage>>> = OnceLock::new();
        REG.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// Register a conflict page. Initially set to RW (the default after loading).
    pub fn register(addr: usize, size: usize) {
        let mut reg = registry().lock().unwrap();
        reg.entry(addr).or_insert(ConflictPage {
            addr,
            size,
            is_exec: false, // starts as RW
        });
    }

    /// Toggle a conflict page's permissions. Returns true if the page was found.
    /// Called from the signal handler - must be async-signal-safe (no allocation).
    /// We use try_lock to avoid deadlock if the signal fires while holding the lock.
    pub fn toggle(fault_addr: usize, need_exec: bool) -> bool {
        let page_size = super::host_page_size();
        let page_addr = fault_addr & !(page_size - 1);

        let mut reg = match registry().try_lock() {
            Ok(r) => r,
            Err(_) => return false, // can't acquire lock in signal handler
        };

        if let Some(cp) = reg.get_mut(&page_addr) {
            let prot = if need_exec {
                libc::PROT_READ | libc::PROT_EXEC
            } else {
                libc::PROT_READ | libc::PROT_WRITE
            };
            let rc = unsafe { libc::mprotect(cp.addr as *mut libc::c_void, cp.size, prot) };
            if rc == 0 {
                cp.is_exec = need_exec;
                return true;
            }
        }
        false
    }

    pub fn has_conflicts() -> bool {
        let reg = registry().lock().unwrap();
        !reg.is_empty()
    }

    /// Public lock accessor for use outside the module (e.g. install_wx_signal_handler).
    pub fn registry_lock() -> std::sync::MutexGuard<'static, HashMap<usize, ConflictPage>> {
        registry().lock().unwrap()
    }
}

/// Install a SIGBUS signal handler that toggles W^X conflict pages on demand.
/// Must be called once, after at least one library with conflict pages is loaded.
#[cfg(target_os = "macos")]
pub fn install_wx_signal_handler() {
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return; // already installed
    }
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = wx_sigbus_handler as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGBUS, &sa, std::ptr::null_mut());
    }
    if init_trace_enabled() {
        eprintln!(
            "[elf_loader] W^X signal handler installed for {} conflict pages",
            {
                let reg = wx_conflict::registry_lock();
                reg.len()
            }
        );
    }
}

#[cfg(not(target_os = "macos"))]
pub fn install_wx_signal_handler() {}

#[cfg(target_os = "macos")]
unsafe extern "C" fn wx_sigbus_handler(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    ucontext: *mut libc::c_void,
) {
    if sig != libc::SIGBUS || info.is_null() || ucontext.is_null() {
        // Not our signal - re-raise
        libc::signal(libc::SIGBUS, libc::SIG_DFL);
        libc::raise(libc::SIGBUS);
        return;
    }

    let fault_addr = (*info).si_addr as usize;

    // Get PC from ucontext to distinguish execute vs write faults.
    // On macOS ARM64, ucontext_t contains __mcontext which has __ss.__pc.
    let uc = ucontext as *const libc::ucontext_t;
    let pc = (*(*uc).uc_mcontext).__ss.__pc as usize;

    let need_exec = fault_addr == pc; // execute fault: si_addr == PC

    if wx_conflict::toggle(fault_addr, need_exec) {
        // Permission toggled - return to retry the faulting instruction
        return;
    }

    // Not a conflict page - re-raise as default
    libc::signal(libc::SIGBUS, libc::SIG_DFL);
    libc::raise(libc::SIGBUS);
}

fn log_unresolved_once(symbol: &str) {
    static UNRESOLVED_SYMBOLS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let unresolved = UNRESOLVED_SYMBOLS.get_or_init(|| Mutex::new(HashSet::new()));
    let mut unresolved = unresolved.lock().unwrap();
    if unresolved.insert(symbol.to_string()) && init_trace_enabled() {
        eprintln!("Warning: Unresolved symbol: {}", symbol);
    }
}

fn align_down(addr: usize, align: usize) -> usize {
    addr & !(align - 1)
}

fn align_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}

fn host_page_size() -> usize {
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if value <= 0 { 0x1000 } else { value as usize }
}

#[derive(Clone)]
struct RegisteredLibrary {
    symbols: HashMap<String, usize>,
    init_fn: Option<usize>,
    init_array: Vec<usize>,
    init_state: InitState,
    #[cfg(target_os = "macos")]
    segment_protections: Vec<(usize, usize, i32)>, // (offset, size, prot)
}

#[derive(Default)]
struct LoadedLibraryRegistry {
    by_handle: HashMap<usize, RegisteredLibrary>,
    handle_by_name: HashMap<String, usize>,
    load_order: Vec<usize>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InitState {
    Uninitialized,
    Initializing,
    Initialized,
}

fn loaded_library_registry() -> &'static Mutex<LoadedLibraryRegistry> {
    static REGISTRY: OnceLock<Mutex<LoadedLibraryRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(LoadedLibraryRegistry::default()))
}

fn normalize_library_name(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

fn name_candidates(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let normalized = normalize_library_name(name);
    if normalized.is_empty() {
        return out;
    }
    out.push(normalized.clone());
    if let Some(file_name) = Path::new(&normalized).file_name() {
        out.push(file_name.to_string_lossy().to_string());
    }
    out.sort();
    out.dedup();
    out
}

fn register_loaded_library(
    path: &Path,
    handle: usize,
    symbols: &HashMap<String, usize>,
    init_fn: Option<usize>,
    init_array: Vec<usize>,
    #[cfg(target_os = "macos")] segment_protections: Vec<(usize, usize, i32)>,
) {
    let mut registry = loaded_library_registry().lock().unwrap();
    let mut aliases = HashSet::new();

    aliases.insert(normalize_library_name(&path.to_string_lossy()));
    if let Ok(canonical) = path.canonicalize() {
        aliases.insert(normalize_library_name(&canonical.to_string_lossy()));
    }
    if let Some(file_name) = path.file_name() {
        aliases.insert(normalize_library_name(&file_name.to_string_lossy()));
    }

    for alias in aliases.iter() {
        if !alias.is_empty() {
            registry.handle_by_name.insert(alias.clone(), handle);
        }
    }

    if !registry.load_order.contains(&handle) {
        registry.load_order.push(handle);
    }

    registry.by_handle.insert(
        handle,
        RegisteredLibrary {
            symbols: symbols.clone(),
            init_fn,
            init_array,
            init_state: InitState::Uninitialized,
            #[cfg(target_os = "macos")]
            segment_protections,
        },
    );
}

fn init_trace_enabled() -> bool {
    std::env::var("XAS_HOOK_TRACE")
        .ok()
        .map(|v| {
            let value = v.to_ascii_lowercase();
            value == "1" || value == "true" || value == "on"
        })
        .unwrap_or(false)
}

fn run_initializer(addr: usize) {
    if addr == 0 {
        return;
    }
    if init_trace_enabled() {
        eprintln!("[init] calling initializer @ {addr:#x}");
    }
    let init: extern "C" fn() = unsafe { std::mem::transmute(addr) };
    init();
}

pub fn ensure_registered_library_initialized(handle: *mut c_void) -> bool {
    let raw_handle = handle as usize;
    if raw_handle == 0 {
        return false;
    }

    let (init_fn, init_array) = {
        let mut registry = loaded_library_registry().lock().unwrap();
        let Some(lib) = registry.by_handle.get_mut(&raw_handle) else {
            return false;
        };
        match lib.init_state {
            InitState::Initialized | InitState::Initializing => {
                return true;
            }
            InitState::Uninitialized => {
                lib.init_state = InitState::Initializing;
                (lib.init_fn, lib.init_array.clone())
            }
        }
    };

    if let Some(addr) = init_fn {
        run_initializer(addr);
    }
    for addr in init_array {
        run_initializer(addr);
    }

    let mut registry = loaded_library_registry().lock().unwrap();
    if let Some(lib) = registry.by_handle.get_mut(&raw_handle) {
        lib.init_state = InitState::Initialized;
    }

    true
}

pub fn clear_registered_libraries() {
    let mut registry = loaded_library_registry().lock().unwrap();
    registry.by_handle.clear();
    registry.handle_by_name.clear();
    registry.load_order.clear();
}

pub fn resolve_symbol_from_registered_libraries(name: &str) -> Option<usize> {
    let registry = loaded_library_registry().lock().unwrap();
    for handle in registry.load_order.iter().rev() {
        if let Some(lib) = registry.by_handle.get(handle)
            && let Some(&addr) = lib.symbols.get(name)
        {
            return Some(addr);
        }
    }
    None
}

pub fn lookup_registered_library_handle(name: &str) -> Option<*mut c_void> {
    let registry = loaded_library_registry().lock().unwrap();
    for candidate in name_candidates(name) {
        if let Some(handle) = registry.handle_by_name.get(&candidate) {
            return Some(*handle as *mut c_void);
        }
    }
    None
}

pub fn lookup_symbol_in_registered_library(handle: *mut c_void, symbol: &str) -> Option<usize> {
    let registry = loaded_library_registry().lock().unwrap();
    let raw_handle = handle as usize;
    let signed = raw_handle as isize;
    let search_all = raw_handle == 0 || signed == -1 || signed == -2;

    if search_all {
        for loaded_handle in registry.load_order.iter().rev() {
            if let Some(lib) = registry.by_handle.get(loaded_handle)
                && let Some(&addr) = lib.symbols.get(symbol)
            {
                return Some(addr);
            }
        }
        return None;
    }

    let lib = registry.by_handle.get(&raw_handle)?;
    lib.symbols.get(symbol).copied()
}

pub fn is_registered_library_handle(handle: *mut c_void) -> bool {
    let registry = loaded_library_registry().lock().unwrap();
    registry.by_handle.contains_key(&(handle as usize))
}

/// Fix PLT page permissions for all loaded libraries.
/// On macOS 16KB pages, overlapping ELF segments can cause .plt to lose
/// EXEC permission. Call this AFTER all libraries are loaded and initialized
/// (init_array has run), so data pages have been written. This restores
/// EXEC on pages that had it from an earlier segment but lost it.
#[cfg(target_os = "macos")]
pub fn fix_plt_exec_permissions() {
    let page_size = host_page_size();
    let registry = loaded_library_registry().lock().unwrap();

    for (&base_addr, lib) in &registry.by_handle {
        let base = base_addr as *mut u8;
        use std::collections::BTreeSet;
        let mut exec_pages = BTreeSet::new();
        let mut final_exec = BTreeSet::new();

        for &(offset, size, prot) in &lib.segment_protections {
            let ps = align_down(offset, page_size);
            let pe = align_up(offset + size, page_size);
            let mut p = ps;
            while p < pe {
                if (prot & libc::PROT_EXEC) != 0 {
                    exec_pages.insert(p);
                }
                if (prot & libc::PROT_EXEC) != 0 {
                    final_exec.insert(p);
                } else {
                    final_exec.remove(&p);
                }
                p += page_size;
            }
        }

        for page_offset in exec_pages.difference(&final_exec) {
            unsafe {
                libc::mprotect(
                    base.add(*page_offset) as *mut libc::c_void,
                    page_size,
                    libc::PROT_READ | libc::PROT_EXEC,
                );
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub fn fix_plt_exec_permissions() {
    // No-op: Linux uses 4KB pages matching ELF segment alignment
}

pub struct LoadedLibrary {
    base: *mut u8,
    size: usize,
    symbols: HashMap<String, usize>,
}

// SAFETY: LoadedLibrary owns an mmap region and immutable symbol metadata after construction.
// Mutations happen through &mut self during loading, before instances enter shared registries.
unsafe impl Send for LoadedLibrary {}
// SAFETY: Shared access only reads base/size/symbols; initialization state is guarded by mutexes.
unsafe impl Sync for LoadedLibrary {}

impl LoadedLibrary {
    pub fn load(path: &Path) -> Result<Self> {
        let file_data =
            std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;

        let elf = Elf::parse(&file_data)
            .with_context(|| format!("Failed to parse ELF: {}", path.display()))?;

        if elf.header.e_machine != goblin::elf::header::EM_X86_64
            && elf.header.e_machine != goblin::elf::header::EM_AARCH64
        {
            bail!(
                "Only x86_64 and aarch64 ELF files are supported, got machine type: {}",
                elf.header.e_machine
            );
        }

        // Calculate total memory needed
        let mut min_vaddr = usize::MAX;
        let mut max_vaddr = 0usize;

        for ph in &elf.program_headers {
            if ph.p_type == PT_LOAD {
                let start = ph.p_vaddr as usize;
                let end = start + ph.p_memsz as usize;
                min_vaddr = min_vaddr.min(start);
                max_vaddr = max_vaddr.max(end);
            }
        }

        if min_vaddr == usize::MAX {
            bail!("No PT_LOAD segments found");
        }

        let page_size = host_page_size();
        let load_size = align_up(max_vaddr - align_down(min_vaddr, page_size), page_size);

        // Allocate memory with RWX permissions using mmap directly for JIT support
        #[cfg(target_os = "macos")]
        let base = unsafe {
            let ptr = libc::mmap(
                std::ptr::null_mut(),
                load_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if ptr == libc::MAP_FAILED {
                bail!("mmap failed: {}", std::io::Error::last_os_error());
            }
            ptr as *mut u8
        };

        #[cfg(not(target_os = "macos"))]
        let base = unsafe {
            let ptr = libc::mmap(
                std::ptr::null_mut(),
                load_size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if ptr == libc::MAP_FAILED {
                bail!("mmap failed: {}", std::io::Error::last_os_error());
            }
            ptr as *mut u8
        };
        let base_offset = align_down(min_vaddr, page_size);

        #[cfg(target_os = "macos")]
        let mut segment_protections: Vec<(usize, usize, i32)> = Vec::new();

        // Load segments
        for ph in &elf.program_headers {
            if ph.p_type == PT_LOAD {
                let vaddr = ph.p_vaddr as usize;
                let offset = vaddr - base_offset;
                let file_offset = ph.p_offset as usize;
                let file_size = ph.p_filesz as usize;

                unsafe {
                    std::ptr::copy_nonoverlapping(
                        file_data.as_ptr().add(file_offset),
                        base.add(offset),
                        file_size,
                    );
                }

                #[cfg(target_os = "macos")]
                {
                    let seg_start = align_down(offset, page_size);
                    let seg_end = align_up(offset + ph.p_memsz as usize, page_size);
                    let mut prot = 0;
                    if (ph.p_flags & PF_R) != 0 {
                        prot |= libc::PROT_READ;
                    }
                    if (ph.p_flags & PF_W) != 0 {
                        prot |= libc::PROT_WRITE;
                    }
                    if (ph.p_flags & PF_X) != 0 {
                        prot |= libc::PROT_EXEC;
                    }
                    segment_protections.push((seg_start, seg_end - seg_start, prot));
                }
            }
        }

        // Build symbol table
        let mut symbols = HashMap::new();
        for sym in &elf.dynsyms {
            if sym.st_type() == STT_FUNC
                && sym.st_value != 0
                && let Some(name) = elf.dynstrtab.get_at(sym.st_name)
            {
                let addr = unsafe { base.add(sym.st_value as usize - base_offset) as usize };
                symbols.insert(name.to_string(), addr);
            }
        }

        // Also add non-function symbols that might be needed
        for sym in &elf.dynsyms {
            if sym.st_value != 0
                && sym.st_type() != STT_FUNC
                && let Some(name) = elf.dynstrtab.get_at(sym.st_name)
                && !symbols.contains_key(name)
            {
                let addr = unsafe { base.add(sym.st_value as usize - base_offset) as usize };
                symbols.insert(name.to_string(), addr);
            }
        }

        let mut lib = Self {
            base,
            size: load_size,
            symbols,
        };

        // Process relocations
        lib.process_relocations(&elf, &file_data, base_offset)?;
        let (init_fn, init_array) = lib.collect_initializers(&elf, base_offset);

        // Apply per-segment protections with W^X conflict detection.
        // On macOS 16KB pages, two ELF segments (e.g. R+X .text/.plt and RW .data/.got)
        // can share a host page. We detect these "conflict pages" and register them
        // for the SIGBUS signal handler to toggle permissions on demand.
        #[cfg(target_os = "macos")]
        {
            use std::collections::BTreeMap;
            // Build per-page permission requirements
            let mut page_needs_exec: BTreeMap<usize, bool> = BTreeMap::new();
            let mut page_needs_write: BTreeMap<usize, bool> = BTreeMap::new();
            let mut page_final_prot: BTreeMap<usize, i32> = BTreeMap::new();

            for &(offset, size, prot) in &segment_protections {
                let ps = align_down(offset, page_size);
                let pe = align_up(offset + size, page_size);
                let mut p = ps;
                while p < pe {
                    if (prot & libc::PROT_EXEC) != 0 {
                        page_needs_exec.insert(p, true);
                    }
                    if (prot & libc::PROT_WRITE) != 0 {
                        page_needs_write.insert(p, true);
                    }
                    // Last segment wins (sequential)
                    page_final_prot.insert(p, prot);
                    p += page_size;
                }
            }

            // Detect conflict pages and register them
            for &page_off in page_needs_exec.keys() {
                if page_needs_write.contains_key(&page_off) {
                    let abs_addr = base as usize + page_off;
                    wx_conflict::register(abs_addr, page_size);
                }
            }

            // Apply permissions: conflict pages get RW (for init), others get final prot
            for (&page_off, &prot) in &page_final_prot {
                let abs_addr = base as usize + page_off;
                let is_conflict = page_needs_exec.contains_key(&page_off)
                    && page_needs_write.contains_key(&page_off);
                let effective_prot = if is_conflict {
                    // Start as RW so init_array code can write to these pages
                    libc::PROT_READ | libc::PROT_WRITE
                } else if prot == 0 {
                    libc::PROT_NONE
                } else {
                    prot
                };
                unsafe {
                    if libc::mprotect(abs_addr as *mut libc::c_void, page_size, effective_prot) != 0
                    {
                        bail!(
                            "mprotect page failed: addr={abs_addr:#x} size={page_size:#x}: {}",
                            std::io::Error::last_os_error()
                        );
                    }
                }
            }
        }

        register_loaded_library(
            path,
            base as usize,
            &lib.symbols,
            init_fn,
            init_array,
            #[cfg(target_os = "macos")]
            segment_protections,
        );

        Ok(lib)
    }

    fn virtual_addr_to_host(&self, vaddr: usize, base_offset: usize) -> Option<usize> {
        if vaddr < base_offset {
            return None;
        }
        let offset = vaddr - base_offset;
        if offset >= self.size {
            return None;
        }
        Some(unsafe { self.base.add(offset) as usize })
    }

    fn normalize_initializer_addr(&self, value: usize, base_offset: usize) -> Option<usize> {
        if value <= 1 {
            return None;
        }
        if value >= self.base as usize && value < self.base as usize + self.size {
            return Some(value);
        }
        if let Some(addr) = self.virtual_addr_to_host(value, base_offset) {
            return Some(addr);
        }
        None
    }

    fn collect_initializers(&self, elf: &Elf, base_offset: usize) -> (Option<usize>, Vec<usize>) {
        let Some(dynamic) = elf.dynamic.as_ref() else {
            return (None, Vec::new());
        };

        let mut init_fn_vaddr = None;
        let mut init_array_vaddr = None;
        let mut init_array_size = 0usize;

        for entry in dynamic.dyns.iter() {
            match entry.d_tag {
                DT_INIT => init_fn_vaddr = Some(entry.d_val as usize),
                DT_INIT_ARRAY => init_array_vaddr = Some(entry.d_val as usize),
                DT_INIT_ARRAYSZ => init_array_size = entry.d_val as usize,
                _ => {}
            }
        }

        let init_fn =
            init_fn_vaddr.and_then(|vaddr| self.normalize_initializer_addr(vaddr, base_offset));
        let mut init_array = Vec::new();

        if let Some(init_array_vaddr) = init_array_vaddr
            && let Some(init_array_host) = self.virtual_addr_to_host(init_array_vaddr, base_offset)
        {
            let count = init_array_size / std::mem::size_of::<usize>();
            for index in 0..count {
                let slot_ptr = (init_array_host as *const u8)
                    .wrapping_add(index * std::mem::size_of::<usize>())
                    as *const usize;
                let entry = unsafe { std::ptr::read_unaligned(slot_ptr) };
                if let Some(addr) = self.normalize_initializer_addr(entry, base_offset) {
                    init_array.push(addr);
                }
            }
        }

        init_array.retain(|&addr| addr != 0);

        if init_trace_enabled() {
            eprintln!(
                "[init] collected init_fn={:?} init_array_count={}",
                init_fn.map(|v| format!("{v:#x}")),
                init_array.len()
            );
        }

        (init_fn, init_array)
    }

    fn process_relocations(
        &mut self,
        elf: &Elf,
        _file_data: &[u8],
        base_offset: usize,
    ) -> Result<()> {
        let hooks = GLOBAL_HOOKS.lock().unwrap();

        // Process RELA relocations
        for reloc in &elf.dynrelas {
            let addend = reloc.r_addend.unwrap_or(0);
            self.apply_relocation(
                elf,
                reloc.r_offset,
                reloc.r_type,
                reloc.r_sym,
                addend,
                base_offset,
                &hooks,
            )?;
        }

        // Process PLT relocations
        for reloc in &elf.pltrelocs {
            let addend = reloc.r_addend.unwrap_or(0);
            self.apply_relocation(
                elf,
                reloc.r_offset,
                reloc.r_type,
                reloc.r_sym,
                addend,
                base_offset,
                &hooks,
            )?;
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_relocation(
        &mut self,
        elf: &Elf,
        r_offset: u64,
        r_type: u32,
        r_sym: usize,
        r_addend: i64,
        base_offset: usize,
        hooks: &HashMap<String, usize>,
    ) -> Result<()> {
        let reloc_addr = unsafe { self.base.add(r_offset as usize - base_offset) as *mut u64 };

        match r_type {
            // goblin defines both NONE relocations as 0.
            R_X86_64_NONE => {}

            R_X86_64_64 | R_AARCH64_ABS64 => {
                let sym = &elf
                    .dynsyms
                    .get(r_sym)
                    .ok_or_else(|| anyhow!("Invalid symbol index"))?;
                let sym_name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("");
                let sym_addr =
                    self.resolve_symbol(sym_name, sym.st_value as usize, base_offset, hooks);
                unsafe {
                    *reloc_addr = (sym_addr as i64 + r_addend) as u64;
                }
            }

            R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT | R_AARCH64_GLOB_DAT | R_AARCH64_JUMP_SLOT => {
                let sym = &elf
                    .dynsyms
                    .get(r_sym)
                    .ok_or_else(|| anyhow!("Invalid symbol index"))?;
                let sym_name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("");
                let sym_addr =
                    self.resolve_symbol(sym_name, sym.st_value as usize, base_offset, hooks);
                unsafe {
                    *reloc_addr = sym_addr as u64;
                }
            }

            R_X86_64_RELATIVE | R_AARCH64_RELATIVE => unsafe {
                *reloc_addr = (self.base as i64 + r_addend - base_offset as i64) as u64;
            },

            R_X86_64_IRELATIVE | R_AARCH64_IRELATIVE => {
                // Indirect relative - resolver function
                // Skip for now to avoid calling potentially invalid code during load
                // let resolver_addr = (self.base as i64 + r_addend - base_offset as i64) as usize;
                // let resolver: extern "C" fn() -> usize = unsafe { std::mem::transmute(resolver_addr) };
                // let resolved = resolver();
                // unsafe {
                //     *reloc_addr = resolved as u64;
                // }
            }

            R_X86_64_COPY => {
                // Skip COPY relocations - they're for executables, not shared libs
            }

            R_X86_64_TPOFF64
            | R_X86_64_DTPMOD64
            | R_X86_64_DTPOFF64
            | R_AARCH64_TLS_TPREL64
            | R_AARCH64_TLS_DTPREL64
            | R_AARCH64_TLS_DTPMOD64 => {
                // TLS relocations - stub for now
                unsafe {
                    *reloc_addr = 0;
                }
            }

            _ => {
                // Don't warn for every relocation - can be noisy
                // eprintln!("Warning: Unsupported relocation type: {}", r_type);
            }
        }

        Ok(())
    }

    fn resolve_symbol(
        &self,
        name: &str,
        sym_value: usize,
        base_offset: usize,
        hooks: &HashMap<String, usize>,
    ) -> usize {
        // First check hooks
        if let Some(&addr) = hooks.get(name) {
            return addr;
        }

        // Then check our own symbols
        if let Some(&addr) = self.symbols.get(name) {
            return addr;
        }

        // Cross-library symbol resolution for preloaded Android dependencies.
        if let Some(addr) = resolve_symbol_from_registered_libraries(name) {
            return addr;
        }

        // If symbol has a value in the library, use it
        if sym_value != 0 {
            return unsafe { self.base.add(sym_value - base_offset) as usize };
        }

        // Try to find in libc via dlsym
        unsafe {
            let libc_handle = libc::dlopen(std::ptr::null(), libc::RTLD_NOW);
            if !libc_handle.is_null() {
                let c_name = std::ffi::CString::new(name).unwrap();
                let addr = libc::dlsym(libc_handle, c_name.as_ptr());
                if !addr.is_null() {
                    return addr as usize;
                }
            }
        }

        // Dynamic fallback for unresolved C++/mediaplatform symbols.
        if let Some(addr) = resolve_dynamic_symbol_fallback(name) {
            return addr;
        }

        log_unresolved_once(name);
        0
    }

    pub fn get_symbol(&self, name: &str) -> Option<usize> {
        self.symbols.get(name).copied()
    }

    pub fn get_symbol_ptr<T>(&self, name: &str) -> Option<*const T> {
        self.get_symbol(name).map(|addr| addr as *const T)
    }

    pub fn handle(&self) -> *mut c_void {
        self.base as *mut c_void
    }
}

impl Drop for LoadedLibrary {
    fn drop(&mut self) {
        let unmap_on_drop = std::env::var("XAS_UNMAP_ON_DROP")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if unmap_on_drop {
            unsafe {
                libc::munmap(self.base as *mut libc::c_void, self.size);
            }
        }
    }
}
