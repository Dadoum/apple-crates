use crate::elf_hash_table::GnuHash;
use crate::elf_library::LibraryLoadingError::{IncompatibleArchitecture, IncompatiblePageLayout};
use crate::*;
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_LOAD};
use goblin::elf::section_header::SHT_GNU_HASH;
use goblin::elf::{Elf, RelocSection};
use log::{trace, warn};
use memmap2::{MmapMut, MmapOptions};
use std::error::Error;
use std::fmt;
use std::marker::PhantomData;
use std::os::raw::c_void;

#[allow(unused_imports)]
use goblin::elf::header::{EM_386, EM_AARCH64, EM_ARM, EM_X86_64};

pub struct Library<'data> {
    elf: Elf<'data>,
    gnu_hash_section: Option<GnuHash<'data, usize>>,
    memory_map: MmapMut,
}

impl<'data> Library<'data> {
    pub fn load<F: Fn(&str) -> Option<*const c_void>>(
        data: &'data [u8],
        symbols: F,
    ) -> Result<Self, LibraryLoadingError> {
        let elf = Elf::parse(data)?;

        let (minimum_address, maximum_address) =
            elf.program_headers
                .iter()
                .fold((usize::MAX, usize::MIN), |(min, max), header| {
                    let start = region::page::floor(header.p_vaddr as *const u8) as usize;
                    let end =
                        region::page::ceil((header.p_vaddr + header.p_memsz) as *const u8) as usize;
                    (usize::min(min, start), usize::max(max, end))
                });

        #[cfg(target_arch = "x86_64")]
        if elf.header.e_machine != EM_X86_64 {
            return Err(IncompatibleArchitecture(elf.header.e_machine));
        }
        #[cfg(target_arch = "aarch64")]
        if elf.header.e_machine != EM_AARCH64 {
            return Err(IncompatibleArchitecture(elf.header.e_machine));
        }
        #[cfg(target_arch = "x86")]
        if elf.header.e_machine != EM_386 {
            return Err(IncompatibleArchitecture(elf.header.e_machine));
        }
        #[cfg(target_arch = "arm")]
        if elf.header.e_machine != EM_ARM {
            return Err(IncompatibleArchitecture(elf.header.e_machine));
        }
        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "x86",
            target_arch = "arm"
        )))]
        warn!("Unknown host architecture.");

        let mut memory_map = MmapOptions::new()
            .len(maximum_address - minimum_address)
            .map_anon()?;

        // let page_size = region::page::size();
        for header in &elf.program_headers {
            if header.p_type != PT_LOAD {
                continue;
            }
            // it's not p_align that we should check.
            // if header.p_align < page_size as u64 {
            //     // Technically, we could use the same tricks as elf-loader 1
            //     // and try to load the library anyway, but it is hacky so for now
            //     // it will just error out.
            //     return Err(IncompatiblePageLayout(header.p_align));
            // }

            let header_data =
                &data[header.p_offset as usize..(header.p_offset + header.p_filesz) as usize];
            memory_map[header.p_vaddr as usize..(header.p_vaddr + header.p_filesz) as usize]
                .copy_from_slice(header_data);
        }

        for header in &elf.program_headers {
            if header.p_type != PT_LOAD {
                continue;
            }

            let start = region::page::floor(&memory_map[header.p_vaddr as usize]);
            let end = region::page::ceil(&memory_map[(header.p_vaddr + header.p_memsz) as usize]);

            let mut flags = region::Protection::NONE.bits();
            if header.p_flags & PF_R != 0 {
                flags |= region::Protection::READ.bits();
            }
            if header.p_flags & PF_W != 0 {
                flags |= region::Protection::WRITE.bits();
            }
            if header.p_flags & PF_X != 0 {
                flags |= region::Protection::EXECUTE.bits();
            }

            unsafe {
                trace!(
                    "Protecting the section {:p} - {:p} with the protection {:03b}",
                    start, end, flags
                );
                region::protect(
                    start,
                    end as usize - start as usize,
                    region::Protection::from_bits_unchecked(flags),
                )?;
            }
        }

        let memory_map_ptr = memory_map.as_ptr() as usize;
        let mut relocate = |relocation_section: &RelocSection| {
            for relocation in relocation_section {
                #[allow(unreachable_patterns)]
                match relocation.r_type {
                    goblin::elf::reloc::R_X86_64_RELATIVE
                    | goblin::elf::reloc::R_386_RELATIVE
                    | goblin::elf::reloc::R_AARCH64_RELATIVE
                    | goblin::elf::reloc::R_ARM_RELATIVE => {
                        let addend = relocation.r_addend.unwrap_or(0) as isize;
                        let value = (memory_map_ptr.wrapping_add_signed(addend)).to_ne_bytes();

                        let offset = relocation.r_offset as usize;

                        memory_map[offset..offset + value.len()].copy_from_slice(&value);
                    }

                    goblin::elf::reloc::R_X86_64_GLOB_DAT
                    | goblin::elf::reloc::R_386_GLOB_DAT
                    | goblin::elf::reloc::R_AARCH64_GLOB_DAT
                    | goblin::elf::reloc::R_ARM_GLOB_DAT
                    | goblin::elf::reloc::R_X86_64_JUMP_SLOT
                    | goblin::elf::reloc::R_386_JMP_SLOT
                    | goblin::elf::reloc::R_AARCH64_JUMP_SLOT
                    | goblin::elf::reloc::R_ARM_JUMP_SLOT
                    | goblin::elf::reloc::R_X86_64_64
                    | goblin::elf::reloc::R_386_32
                    | goblin::elf::reloc::R_AARCH64_ABS64
                    | goblin::elf::reloc::R_ARM_ABS32 => {
                        let requested_symbol = elf
                            .dynsyms
                            .get(relocation.r_sym)
                            .map(|sym| &elf.dynstrtab[sym.st_name])
                            .and_then(&symbols)
                            .unwrap_or(unknown_symbol as *const c_void)
                            as usize;

                        let addend = relocation.r_addend.unwrap_or(0) as isize;
                        let value = requested_symbol.wrapping_add_signed(addend).to_ne_bytes();

                        let offset = relocation.r_offset as usize;

                        memory_map[offset..offset + value.len()].copy_from_slice(&value);
                    }

                    _ => {
                        warn!("Unknown relocation: {:?}", relocation);
                    }
                }
            }
        };

        relocate(&elf.dynrelas);
        relocate(&elf.dynrels);

        let gnu_hash_section = elf
            .section_headers
            .iter()
            .find(|section| section.sh_type == SHT_GNU_HASH)
            .map(|section| unsafe {
                GnuHash::<usize>::from_raw_data(
                    &data[section.sh_addr as usize
                        ..section.sh_addr as usize + section.sh_size as usize],
                )
            });

        Ok(Self {
            elf,
            gnu_hash_section, // TODO
            memory_map,
        })
    }

    pub fn get<'library, T: Copy>(
        &'library self,
        symbol_name: &str,
    ) -> Option<Symbol<'library, 'data, T>> {
        let sym = match &self.gnu_hash_section {
            Some(hash_table) => {
                hash_table.find(symbol_name, &self.elf.dynsyms, &self.elf.dynstrtab)
            }
            None => self
                .elf
                .dynsyms
                .iter()
                .find(|symbol| &self.elf.dynstrtab[symbol.st_name] == symbol_name),
        };

        sym.map(|sym| unsafe {
            let value: *const T = std::mem::transmute(&&self.memory_map[sym.st_value as usize]);
            Symbol {
                ptr: *value,
                library: PhantomData,
            }
        })
    }
}

#[linux_cc]
fn unknown_symbol() -> ! {
    panic!("Unknown symbol called.");
}

#[derive(Debug)]
pub enum LibraryLoadingError {
    IncompatibleArchitecture(u16),
    IncompatiblePageLayout(u64),
    ElfLoadingError(goblin::error::Error),
    IOError(std::io::Error),
    MemoryProtectionError(region::Error),
}

impl std::fmt::Display for LibraryLoadingError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IncompatibleArchitecture(architecture) => write!(
                f,
                "Incompatible architecture (e_machine = {})",
                architecture
            ),
            IncompatiblePageLayout(page_size) => write!(
                f,
                "Incompatible page layout: The executable requires a page size aligned with {} bytes",
                page_size
            ),
            LibraryLoadingError::ElfLoadingError(err) => write!(f, "Unable to load elf: {}", err),
            LibraryLoadingError::IOError(err) => write!(f, "IO error: {}", err),
            LibraryLoadingError::MemoryProtectionError(err) => {
                write!(f, "Cannot protect the memory correctly: {}", err)
            }
        }
    }
}
impl Error for LibraryLoadingError {}

impl From<goblin::error::Error> for LibraryLoadingError {
    fn from(err: goblin::error::Error) -> Self {
        LibraryLoadingError::ElfLoadingError(err)
    }
}

impl From<std::io::Error> for LibraryLoadingError {
    fn from(err: std::io::Error) -> Self {
        LibraryLoadingError::IOError(err)
    }
}

impl From<region::Error> for LibraryLoadingError {
    fn from(err: region::Error) -> Self {
        LibraryLoadingError::MemoryProtectionError(err)
    }
}

pub struct Symbol<'library, 'data, T: Copy> {
    pub ptr: T,
    library: PhantomData<&'library Library<'data>>,
}
