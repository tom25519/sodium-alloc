//! [`Allocator`](std::alloc::Allocator) type that allocates memory using
//! [Sodium](https://doc.libsodium.org/)'s secure memory utilities.
//!
//! **Requires nightly Rust**, as the `Allocator` API is not yet stable.
//!
//! This library implements [`SodiumAllocator`], an `Allocator` which uses the
//! [`sodium_malloc`](https://doc.libsodium.org/memory_management#guarded-heap-allocations) and
//! corresponding `sodium_free` functions to manage memory. When managing sensitive data in memory,
//! there are a number of steps we can take to help harden our software against revealing these
//! secrets.
//!
//! Sodium's `sodium_malloc` implementation introduces many of these hardening steps to the memory
//! management process: Allocated memory is placed at the end of a page boundary, immediately
//! followed by a guard page (a region of memory which is marked as inaccessible, any attempt to
//! access it will result in termination of the program). A canary is placed before the allocated
//! memory, any modifications to which are detected on free, again resulting in program
//! termination, and a guard page is placed before this.
//! [`sodium_mlock`](https://doc.libsodium.org/memory_management#locking-memory) is used to
//! instruct the operating system not to swap the memory to disk, or to include it in core dumps.
//!
//! When memory is freed with `SodiumAllocator`, the `sodium_free` function is called, which will
//! securely zero the memory before marking it as free. This means that for types allocated with
//! `SodiumAllocator`, there is no need to implement `Zeroize` or a similar `Drop` implementation
//! to zero the memory when no longer in use: It will automatically be zeroed when freed.
//!
//! This library is not suitable for use as a general-purpose allocator or global allocator: The
//! overhead of this API is *much* greater than Rust's standard allocator, and the implementation
//! is more likely to encounter errors. It is intended for use when allocating sensitive data types
//! only, for example, a key or password which needs to be stored in memory.
//!
//! ## Examples
//! Here we create a standard Rust vector, but use Sodium's memory management to allocate/grow/free
//! its memory:
//!
//! ```
//! // Currently necessary: Allocators are feature-gated on nightly
//! #![feature(allocator_api)]
//!
//! use std::alloc::Allocator;
//! use sodium_alloc::SodiumAllocator;
//!
//! // Allocate a vector using Sodium's memory management functions
//! let mut my_vec = Vec::with_capacity_in(4, SodiumAllocator);
//! my_vec.push(0);
//! my_vec.push(1);
//! my_vec.extend_from_slice(&[3, 4]);
//! println!("{:?}", my_vec);
//! // Grow the vector, works just like normal :)
//! my_vec.reserve(10);
//! // Drop the vector, the SodiumAllocator will securely zero the memory when freed. Dropping like
//! // this isn't necessary, things going out of scope as normal works too, this is just for
//! // illustrative purposes.
//! std::mem::drop(my_vec);
//! ```
//!
//! Boxes also currently support the Allocator API:
//!
//! ```
//! #![feature(allocator_api)]
//!
//! use std::alloc::Allocator;
//! use sodium_alloc::SodiumAllocator;
//!
//! // Store something on the heap, allocating memory with Sodium
//! let key = Box::new_in([0xca, 0xfe, 0xba, 0xbe], SodiumAllocator);
//! println!("{:x?}", key);
//! ```
#![doc(html_root_url = "https://docs.rs/sodium-alloc/0.1.0")]
#![feature(allocator_api)]
#![feature(nonnull_slice_from_raw_parts)]
#![feature(slice_ptr_get)]
#![feature(slice_ptr_len)]

use libsodium_sys as sodium;
use std::alloc::{AllocError, Allocator, Layout};
use std::ffi::c_void;
use std::ptr::NonNull;

/// An [`Allocator`](std::alloc::Allocator) which allocates and frees memory using Sodium's secure
/// memory utilities.
///
/// Allocation of memory using this struct is expensive - it shouldn't be used as a global
/// allocator, but rather confied to manage memory for data structures storing sensitive
/// information, such as keys, passwords, etc.
///
/// When this Allocator frees memory, it is securely zeroed, so there is no need to implement
/// Zeroize or similar constructions for types with memory managed via this struct.
///
/// If the canary Sodium places before the allocated memory is altered, or if an attempt to access
/// a guard page surrounding the allocated memory is made, the program will automatically
/// terminate. This behaviour should never occur in safe Rust.
#[derive(Copy, Clone, Debug)]
pub struct SodiumAllocator;

unsafe impl Allocator for SodiumAllocator {
    fn allocate(&self, mut layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        // Initialise libsodium, okay to call this multiple times from multiple threads, the actual
        // initialisation will only happen once.
        // We don't call this in other functions, as it's assumed we have to have called
        // `Self::allocate` to get some memory to do other things with (e.g: deallocate, grow).
        init()?;

        // Increase the size of the layout so it's a multiple of layout.align - as Sodium allocates
        // memory at the end of the page, as long as the layout size is a multiple of the
        // alignment, and the alignment is a power of 2, the allocation will be correctly aligned.
        layout = layout.pad_to_align();

        // Calling `sodium_malloc` with a size that's a multiple of n produces a pointer aligned to
        // n.
        // SAFETY: This function returns a pointer to `layout.size()` of allocated memory, or NULL
        // if allocation failed. We immediately check for NULL in the next line, and return an
        // error if it occurs. If the result is not NULL, Sodium guarantees that the pointer will
        // reference at least `layout.size()` of allocated, mutable memory.
        let ptr = unsafe { sodium::sodium_malloc(layout.size()) as *mut u8 };
        // NonNull::new() will return Some if `ptr` was non-null, but will return None if `ptr` was
        // null. We convert the latter result into an error.
        let ptr = NonNull::new(ptr).ok_or(AllocError)?;

        Ok(NonNull::slice_from_raw_parts(ptr, layout.size()))
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, _layout: Layout) {
        sodium::sodium_free(ptr.as_ptr() as *mut c_void);
    }

    // We just use the default implementations of the other methods: Sodium doesn't provide any API
    // to grow/shrink memory, so we would have to just allocate new memory then copy for any of
    // these types of operations, which is what the default operations already do.
}

/// Initialise libsodium.
///
/// Called automatically when an attempt to allocate is made.
fn init() -> Result<(), AllocError> {
    unsafe {
        if sodium::sodium_init() >= 0 {
            Ok(())
        } else {
            Err(AllocError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::Layout;
    use std::error::Error;

    #[test]
    fn basic_allocation() -> Result<(), Box<dyn Error>> {
        // Tries to allocate up to 0.5GiB
        for i in 0..29 {
            let layout = Layout::from_size_align(1 << i, 1)?;
            let ptr = SodiumAllocator.allocate(layout)?;

            assert_eq!(ptr.len(), 1 << i);

            unsafe {
                SodiumAllocator.deallocate(ptr.cast(), layout);
            }
        }
        Ok(())
    }

    #[test]
    fn alignment_correct() -> Result<(), Box<dyn Error>> {
        // Test some repeated allocations, ensure that they're always aligned correctly
        for _ in 0..100 {
            let layout_a = Layout::from_size_align(13, 4)?;
            let ptr_a = SodiumAllocator.allocate(layout_a)?;
            assert_eq!(ptr_a.as_ptr() as *mut () as u8 % 4, 0);

            let layout_b = Layout::from_size_align(12, 4)?;
            let ptr_b = SodiumAllocator.allocate(layout_b)?;
            assert_eq!(ptr_b.as_ptr() as *mut () as u8 % 4, 0);

            let layout_c = Layout::from_size_align(20, 16)?;
            let ptr_c = SodiumAllocator.allocate(layout_c)?;
            assert_eq!(ptr_c.as_ptr() as *mut () as u8 % 16, 0);

            unsafe {
                SodiumAllocator.deallocate(ptr_a.cast(), layout_a);
                SodiumAllocator.deallocate(ptr_b.cast(), layout_b);
                SodiumAllocator.deallocate(ptr_c.cast(), layout_c);
            }
        }

        Ok(())
    }

    #[test]
    fn zero_size_alloc() -> Result<(), Box<dyn Error>> {
        let layout = Layout::from_size_align(0, 1)?;
        let ptr = SodiumAllocator.allocate(layout)?;

        assert_eq!(ptr.len(), 0);

        unsafe {
            SodiumAllocator.deallocate(ptr.cast(), layout);
        }

        Ok(())
    }

    #[test]
    fn test_writing() {
        for i in 0..29 {
            let mut v: Vec<u8, _> = Vec::with_capacity_in(1 << i, SodiumAllocator);
            for _ in 0..(1 << i) {
                v.push(0x13);
            }
        }
    }
}
