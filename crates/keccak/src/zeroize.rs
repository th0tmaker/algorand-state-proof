// crates/keccak/src/zeroize.rs

use std::sync::atomic::{compiler_fence, Ordering};

/// In-place zeroing of secret memory.
///
/// Uses `write_volatile` to prevent the compiler from eliding the writes as
/// dead stores, and `compiler_fence(SeqCst)` to prevent them from being
/// reordered past the fence at compile time. No CPU fence is emitted —
/// cross-thread visibility of the zeroing is not a concern.
pub trait Zeroize {
    fn zeroize(&mut self);
}

impl Zeroize for [u8] {
    fn zeroize(&mut self) {
        for byte in self.iter_mut() {
            unsafe { std::ptr::write_volatile(byte, 0u8) }
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl<const N: usize> Zeroize for [u8; N] {
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl Zeroize for [u64] {
    fn zeroize(&mut self) {
        for word in self.iter_mut() {
            unsafe { std::ptr::write_volatile(word, 0u64) }
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl<const N: usize> Zeroize for [u64; N] {
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}
