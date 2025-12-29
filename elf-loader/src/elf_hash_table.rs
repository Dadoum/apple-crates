use goblin::elf::{Sym, Symtab};
use goblin::strtab::Strtab;
use std::{mem, slice};

pub trait Numeric: Copy + std::ops::BitAnd<Self, Output = Self> {}

impl Numeric for u32 {}
impl Numeric for u64 {}
impl Numeric for usize {}

#[allow(unused)]
pub struct GnuHash<'a, T: Numeric> {
    symindex: u32,
    shift2: u32,
    bloom_filter: &'a [T],
    buckets: &'a [u32],
    chains: &'a [u32],
}

impl<'a, T: Numeric> GnuHash<'a, T> {
    pub unsafe fn from_raw_data(raw_data: &'a [u8]) -> Self {
        assert!(raw_data.len() >= size_of::<[u32; 4]>());
        let [nbuckets, symindex, maskwords, shift2] =
            unsafe { (raw_data.as_ptr() as *const u32 as *const [u32; 4]).read() };

        let hashtab: &'a [u8] = &raw_data[16..];

        let (bloom_filter_bytes, hashtab) =
            hashtab.split_at(maskwords as usize * mem::size_of::<T>());
        let (buckets_bytes, chains_bytes) =
            hashtab.split_at(nbuckets as usize * mem::size_of::<u32>());

        unsafe {
            Self {
                symindex,
                shift2,
                bloom_filter: bloom_filter_bytes.transmute(),
                buckets: buckets_bytes.transmute(),
                chains: chains_bytes.transmute(),
            }
        }
    }

    fn lookup(&self, symbol: &str, hash: u32, dynsyms: &Symtab, dynstrtab: &Strtab) -> Option<Sym> {
        const MASK_LOWEST_BIT: u32 = 0xffff_fffe;
        let bucket = self.buckets[hash as usize % self.buckets.len()];

        // Empty hash chain, symbol not present
        if bucket < self.symindex {
            return None;
        }

        // Walk the chain until the symbol is found or the chain is exhausted.
        let chain_idx = bucket - self.symindex;
        let hash = hash & MASK_LOWEST_BIT;
        let chains = &self.chains.get((chain_idx as usize)..)?;
        for (hash2, symb) in chains.iter().zip(dynsyms.iter().skip(bucket as usize)) {
            if (hash == (hash2 & MASK_LOWEST_BIT)) && (symbol == &dynstrtab[symb.st_name]) {
                return Some(symb);
            }
            // Chain ends with an element with the lowest bit set to 1.
            if hash2 & 1 == 1 {
                break;
            }
        }
        None
    }

    // const ELFCLASS_BITS: u64 = (mem::size_of::<T>() * 8) as u64;
    // const MASK: u64 = Self::ELFCLASS_BITS - 1;
    //
    // /// Check if symbol maybe is in the hash table, or definitely not in it.
    // #[inline]
    // fn check_maybe_match(&self, hash: u32) -> bool {
    //     let hash = hash as u64;
    //     let hash2: u64 = hash >> self.shift2;
    //     // `x & (N - 1)` is equivalent to `x % N` iff `N = 2^y`.
    //     let bitmask: u64 = 1 << (hash & (Self::MASK)) | 1 << (hash2 & Self::MASK);
    //     let bloom_idx: u64 = (hash / Self::ELFCLASS_BITS) & (self.bloom_filter.len() as u64 - 1);
    //     let bitmask_word: u64 = self.bloom_filter[bloom_idx as usize];
    //     (bitmask_word & bitmask) == bitmask
    // }

    /// This function will not check if the passed `hash` is really
    /// the hash of `symbol`
    pub fn find_with_hash(
        &self,
        symbol: &str,
        hash: u32,
        dynsym: &Symtab,
        dynstrtab: &Strtab,
    ) -> Option<Sym> {
        // HACK: Bloom filter has not been implemented.
        // if self.check_maybe_match(hash) {
        self.lookup(symbol, hash, dynsym, dynstrtab)
        // } else {
        //     None
        // }
    }

    /// Given a symbol, a hash of that symbol, a dynamic string table and
    /// a `dynstrtab` to cross-reference names, maybe returns a Sym.
    pub(crate) fn find(&self, symbol: &str, dynsym: &Symtab, dynstrtab: &Strtab) -> Option<Sym> {
        let hash = self::hash(symbol);
        self.find_with_hash(symbol, hash, dynsym, dynstrtab)
    }
}

pub fn hash(symbol: &str) -> u32 {
    const HASH_SEED: u32 = 5381;
    symbol.bytes().fold(HASH_SEED, |hash, b| {
        hash.wrapping_mul(33).wrapping_add(u32::from(b))
    })
}

trait Transmute<T: Sized> {
    unsafe fn transmute(&self) -> &[T];
}

impl<T: Sized> Transmute<T> for [u8] {
    unsafe fn transmute(&self) -> &[T] {
        unsafe {
            slice::from_raw_parts(self.as_ptr() as *const T, self.len() / mem::size_of::<T>())
        }
    }
}
