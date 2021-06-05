# sodium-alloc
[![crates.io](https://img.shields.io/crates/v/sodium-alloc.svg)](https://crates.io/crates/sodium-alloc)
[![docs.rs](https://docs.rs/sodium-alloc/badge.svg)](https://docs.rs/sodium-alloc)

Rust [`Allocator`](https://doc.rust-lang.org/std/alloc/trait.Allocator.html)
type that allocates memory using [Sodium](https://doc.libsodium.org/)'s secure
memory utilities.

**Requires nightly Rust**, as the `Allocator` API is not yet stable.

This library implements `SodiumAllocator`, an `Allocator` which uses the
[`sodium_malloc`](https://doc.libsodium.org/memory_management#guarded-heap-allocations)
and corresponding `sodium_free` functions to manage memory. When managing
sensitive data in memory, there are a number of steps we can take to help harden
our software against revealing these secrets.

Sodium's `sodium_malloc` implementation introduces many of these hardening steps
to the memory management process: Allocated memory is placed at the end of a
page boundary, immediately followed by a guard page (a region of memory which is
marked as inaccessible, any attempt to access it will result in termination of
the program). A canary is placed before the allocated memory, any modifications
to which are detected on free, again resulting in program termination, and a
guard page is placed before this.
[`sodium_mlock`](https://doc.libsodium.org/memory_management#locking-memory) is
used to instruct the operating system not to swap the memory to disk, or to
include it in core dumps.

When memory is freed with `SodiumAllocator`, the `sodium_free` function is
called, which will securely zero the memory before marking it as free. This
means that for types allocated with `SodiumAllocator`, there is no need to
implement `Zeroize` or a similar `Drop` implementation to zero the memory when
no longer in use: It will automatically be zeroed when freed.

This library is not suitable for use as a general-purpose allocator or global
allocator: The overhead of this API is *much* greater than Rust's standard
allocator, and the implementation is more likely to encounter errors. It is
intended for use when allocating sensitive data types only, for example, a key
or password which needs to be stored in memory.

## Security/Vulnerability Disclosures
If you find a vulnerability in sodium-alloc, please immediately contact
`tom25519@pm.me` with details.

My [age](https://github.com/FiloSottile/age) public key (preferred) is:

```text
age1gglesedq4m2z9kc7urjhq3zlpc6qewcwpcna7s0lwh8k2c4e6fxqf3kdvq
```

My PGP public key has fingerprint `0x4712EC7C9F404B14`, and is available from
[keyserver.ubuntu.com](https://keyserver.ubuntu.com),
[pgp.mit.edu](https://pgp.mit.edu/), or
[Github](https://github.com/tom25519.gpg).

## License
Licensed under either of:

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

## Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
