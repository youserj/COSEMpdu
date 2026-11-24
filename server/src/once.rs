//! One-time-initialized static storage without atomics.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;

/// One-time-initialized static storage: [`init`](Self::init) hands out a
/// `&'static mut T` once and panics on the second call.
///
/// Unlike `static_cell`, the flag is guarded by a critical section instead of
/// atomics, so this works on targets without atomic instructions (e.g.
/// `riscv32imc`). On `no_std` targets exactly one `critical-section`
/// implementation must be linked (a chip HAL, or `critical-section-single-core`).
pub struct OnceCell<T> {
    used: UnsafeCell<bool>,
    value: UnsafeCell<MaybeUninit<T>>,
}

// SAFETY: `used` and `value` are only accessed inside a critical section, and
// `init` hands out a `&mut T` exactly once (the second call panics).
unsafe impl<T: Send> Sync for OnceCell<T> {}

impl<T> OnceCell<T> {
    pub const fn new() -> Self {
        Self {
            used: UnsafeCell::new(false),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// Write `value` and return a mutable reference to it.
    ///
    /// # Panics
    ///
    /// If the cell has already been initialized.
    pub fn init(&self, value: T) -> &'static mut T {
        critical_section::with(|_| {
            // SAFETY: the flag and the value are touched only inside a critical
            // section, and the `&mut` is handed out only once (guarded by `used`).
            unsafe {
                if *self.used.get() {
                    panic!("OnceCell initialized twice");
                }
                *self.used.get() = true;
                (*self.value.get()).write(value);
                &mut *(*self.value.get()).as_mut_ptr()
            }
        })
    }
}

impl<T> Default for OnceCell<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::OnceCell;

    #[test]
    fn init_returns_the_value_once() {
        static CELL: OnceCell<u32> = OnceCell::new();
        let value = CELL.init(7);
        assert_eq!(*value, 7);
        *value = 8;
        assert_eq!(*value, 8);
    }

    #[test]
    #[should_panic(expected = "OnceCell initialized twice")]
    fn init_twice_panics() {
        static CELL: OnceCell<u32> = OnceCell::new();
        let _ = CELL.init(1);
        let _ = CELL.init(2);
    }
}
