use cfg_if::cfg_if;
use core::hash::{BuildHasher, Hash, Hasher};

// Faster hashers.
cfg_if! {
    if #[cfg(feature = "map-fxhash")] {
        #[doc(no_inline)]
        pub use rustc_hash::{self, FxHasher};

        cfg_if! {
            if #[cfg(all(feature = "std", feature = "rand"))] {
                use rustc_hash::FxRandomState as FxBuildHasherInner;
            } else {
                use rustc_hash::FxBuildHasher as FxBuildHasherInner;
            }
        }

        /// The [`FxHasher`] hasher builder.
        ///
        /// This is [`rustc_hash::FxBuildHasher`], unless both the "std" and "rand" features are
        /// enabled, in which case it will be [`rustc_hash::FxRandomState`] for better security at
        /// very little cost.
        pub type FxBuildHasher = FxBuildHasherInner;
    }
}

#[cfg(feature = "map-foldhash")]
#[doc(no_inline)]
pub use foldhash;

// Default hasher.
cfg_if! {
    if #[cfg(target_os = "zkvm")] {
        type DefaultHashBuilderInner = WordBuildHasher;
    } else if #[cfg(feature = "map-foldhash")] {
        type DefaultHashBuilderInner = foldhash::fast::RandomState;
    } else if #[cfg(feature = "map-fxhash")] {
        type DefaultHashBuilderInner = FxBuildHasher;
    } else if #[cfg(any(feature = "map-hashbrown", not(feature = "std")))] {
        type DefaultHashBuilderInner = hashbrown::DefaultHashBuilder;
    } else {
        type DefaultHashBuilderInner = std::collections::hash_map::RandomState;
    }
}

/// The default [`BuildHasher`] used by [`HashMap`](super::HashMap) and [`HashSet`](super::HashSet).
///
/// See [the module documentation](super) for more information on the default hasher.
#[derive(Clone, Default)]
#[allow(missing_copy_implementations, missing_debug_implementations)]
pub struct DefaultHashBuilder {
    inner: DefaultHashBuilderInner,
}

impl BuildHasher for DefaultHashBuilder {
    type Hasher = DefaultHasher;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        DefaultHasher { inner: self.inner.build_hasher() }
    }

    #[inline]
    fn hash_one<T: Hash>(&self, x: T) -> u64
    where
        Self: Sized,
        Self::Hasher: Hasher,
    {
        self.inner.hash_one(x)
    }
}

/// The default [`Hasher`] used by [`HashMap`](super::HashMap) and [`HashSet`](super::HashSet).
///
/// See [the module documentation](super) for more information on the default hasher.
#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct DefaultHasher {
    inner: <DefaultHashBuilderInner as BuildHasher>::Hasher,
}

macro_rules! forward_writes {
    ($( $write:ident ( $ty:ty ) , )*) => {$(
        #[inline(always)]
        fn $write(&mut self, arg: $ty) {
            self.inner.$write(arg);
        }
    )*}
}

impl Hasher for DefaultHasher {
    forward_writes! {
        write(&[u8]),
        write_u8(u8),
        write_u16(u16),
        write_u32(u32),
        write_u64(u64),
        write_u128(u128),
        write_usize(usize),
        write_i8(i8),
        write_i16(i16),
        write_i32(i32),
        write_i64(i64),
        write_i128(i128),
        write_isize(isize),
    }

    // feature(hasher_prefixfree_extras)
    #[cfg(feature = "nightly")]
    forward_writes! {
        write_length_prefix(usize),
        write_str(&str),
    }

    #[inline(always)]
    fn finish(&self) -> u64 {
        self.inner.finish()
    }
}

/// A word-at-a-time multiplicative hasher for 32-bit zkVM guests.
///
/// Each 32-bit word `w` updates the state as `h = (rotl(h, 5) ^ w) * K`, one
/// 32x32 multiplication per word; [`finish`](Hasher::finish) folds the high
/// bits into the low ones, `h ^= h >> 15; h *= K; h ^= h >> 13`, since
/// hashbrown takes the bucket index from the low bits of the hash and the
/// control byte from bits 25..32 on a 32-bit target.  The guest's inputs are
/// fixed by the block, so the keyed seeds of the host hashers buy nothing here.
#[cfg(target_os = "zkvm")]
#[derive(Clone, Copy, Default)]
#[allow(missing_debug_implementations)]
pub struct WordBuildHasher;

#[cfg(target_os = "zkvm")]
impl BuildHasher for WordBuildHasher {
    type Hasher = WordHasher;

    #[inline(always)]
    fn build_hasher(&self) -> WordHasher {
        WordHasher { h: 0 }
    }
}

/// The [`Hasher`] of [`WordBuildHasher`].
#[cfg(target_os = "zkvm")]
#[derive(Clone, Copy)]
#[allow(missing_debug_implementations)]
pub struct WordHasher {
    h: u32,
}

#[cfg(target_os = "zkvm")]
const WORD_K: u32 = 0x93d7_65dd;

#[cfg(target_os = "zkvm")]
impl WordHasher {
    #[inline(always)]
    fn word(&mut self, w: u32) {
        self.h = (self.h.rotate_left(5) ^ w).wrapping_mul(WORD_K);
    }
}

#[cfg(target_os = "zkvm")]
impl Hasher for WordHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut chunks = bytes.chunks_exact(4);
        for c in &mut chunks {
            self.word(u32::from_le_bytes([c[0], c[1], c[2], c[3]]));
        }
        let rest = chunks.remainder();
        if !rest.is_empty() {
            let mut b = [0u8; 4];
            b[..rest.len()].copy_from_slice(rest);
            self.word(u32::from_le_bytes(b) ^ ((rest.len() as u32) << 30));
        }
    }

    #[inline(always)]
    fn write_u8(&mut self, i: u8) {
        self.word(i as u32);
    }

    #[inline(always)]
    fn write_u16(&mut self, i: u16) {
        self.word(i as u32);
    }

    #[inline(always)]
    fn write_u32(&mut self, i: u32) {
        self.word(i);
    }

    #[inline(always)]
    fn write_u64(&mut self, i: u64) {
        self.word(i as u32);
        self.word((i >> 32) as u32);
    }

    #[inline(always)]
    fn write_usize(&mut self, i: usize) {
        self.word(i as u32);
    }

    #[inline(always)]
    fn finish(&self) -> u64 {
        let mut h = self.h;
        h ^= h >> 15;
        h = h.wrapping_mul(WORD_K);
        h ^= h >> 13;
        h as u64
    }
}
