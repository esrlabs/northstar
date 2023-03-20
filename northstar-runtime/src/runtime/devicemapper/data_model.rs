use std::{
    io,
    mem::{size_of, MaybeUninit},
    slice::{from_raw_parts, from_raw_parts_mut},
};

/// Types for which it is safe to initialize from raw data.
///
///
/// Implementing this trait guarantees that it is safe to instantiate the struct with random data.
///
/// # Safety
/// A type `T` is `DataInit` if it can be initialized by reading its contents from a byte array.
/// This is generally true for all plain-old-data structs.  It is notably not true for any type
/// that includes a reference.
///
/// It is unsafe for `T` to be `DataInit` if `T` contains implicit padding. (LLVM considers access
/// to implicit padding to be undefined behavior, which can cause UB when working with `T`.
/// For details on structure padding in Rust, see
/// <https://doc.rust-lang.org/reference/type-layout.html#the-c-representation>.
pub unsafe trait DataInit: Copy + Send + Sync {
    /// Converts a slice of raw data into a reference of `Self`.
    ///
    /// The value of `data` is not copied. Instead a reference is made from the given slice. The
    /// value of `Self` will depend on the representation of the type in memory, and may change in
    /// an unstable fashion.
    ///
    /// This will return `None` if the length of data does not match the size of `Self`, or if the
    /// data is not aligned for the type of `Self`.
    fn from_slice(data: &[u8]) -> Option<&Self> {
        // Early out to avoid an unneeded `align_to` call.
        if data.len() != size_of::<Self>() {
            return None;
        }

        // Safe because the DataInit trait asserts any data is valid for this type, and we ensured
        // the size of the pointer's buffer is the correct size. The `align_to` method ensures that
        // we don't have any unaligned references. This aliases a pointer, but because the pointer
        // is from a const slice reference, there are no mutable aliases. Finally, the reference
        // returned can not outlive data because they have equal implicit lifetime constraints.
        match unsafe { data.align_to::<Self>() } {
            ([], [mid], []) => Some(mid),
            _ => None,
        }
    }

    /// Copies the value of `Self` from the beginning of a slice of raw data.
    ///
    /// This will return `None` if the length of data is less than the size of `Self`, or if the
    /// data is not aligned for the type of `Self`.
    fn read_from_prefix(data: &[u8]) -> Option<Self> {
        data.get(0..size_of::<Self>())
            .and_then(|slice| Self::from_slice(slice))
            .copied()
    }

    /// Converts a mutable slice of raw data into a mutable reference of `Self`.
    ///
    /// Because `Self` is made from a reference to the mutable slice`, mutations to the returned
    /// reference are immediately reflected in `data`. The value of the returned `Self` will depend
    /// on the representation of the type in memory, and may change in an unstable fashion.
    ///
    /// This will return `None` if the length of data does not match the size of `Self`, or if the
    /// data is not aligned for the type of `Self`.
    fn from_mut_slice(data: &mut [u8]) -> Option<&mut Self> {
        // Early out to avoid an unneeded `align_to_mut` call.
        if data.len() != size_of::<Self>() {
            return None;
        }

        // Safe because the DataInit trait asserts any data is valid for this type, and we ensured
        // the size of the pointer's buffer is the correct size. The `align_to` method ensures that
        // we don't have any unaligned references. This aliases a pointer, but because the pointer
        // is from a mut slice reference, we borrow the passed in mutable reference. Finally, the
        // reference returned can not outlive data because they have equal implicit lifetime
        // constraints.
        match unsafe { data.align_to_mut::<Self>() } {
            ([], [mid], []) => Some(mid),
            _ => None,
        }
    }

    /// Creates an instance of `Self` by copying raw data from an io::Read stream.
    fn from_reader<R: io::Read>(mut read: R) -> io::Result<Self> {
        // Allocate on the stack via `MaybeUninit` to ensure proper alignment.
        let mut out = MaybeUninit::zeroed();

        // Safe because the pointer is valid and points to `size_of::<Self>()` bytes of zeroes,
        // which is a properly initialized value for `u8`.
        let buf = unsafe { from_raw_parts_mut(out.as_mut_ptr() as *mut u8, size_of::<Self>()) };
        read.read_exact(buf)?;

        // Safe because any bit pattern is considered a valid value for `Self`.
        Ok(unsafe { out.assume_init() })
    }

    /// Converts a reference to `self` into a slice of bytes.
    ///
    /// The value of `self` is not copied. Instead, the slice is made from a reference to `self`.
    /// The value of bytes in the returned slice will depend on the representation of the type in
    /// memory, and may change in an unstable fashion.
    fn as_slice(&self) -> &[u8] {
        // Safe because the entire size of self is accessible as bytes because the trait guarantees
        // it. The lifetime of the returned slice is the same as the passed reference, so that no
        // dangling pointers will result from this pointer alias.
        unsafe { from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }

    /// Converts a mutable reference to `self` into a mutable slice of bytes.
    ///
    /// Because the slice is made from a reference to `self`, mutations to the returned slice are
    /// immediately reflected in `self`. The value of bytes in the returned slice will depend on
    /// the representation of the type in memory, and may change in an unstable fashion.
    fn as_mut_slice(&mut self) -> &mut [u8] {
        // Safe because the entire size of self is accessible as bytes because the trait guarantees
        // it. The trait also guarantees that any combination of bytes is valid for this type, so
        // modifying them in the form of a byte slice is valid. The lifetime of the returned slice
        // is the same as the passed reference, so that no dangling pointers will result from this
        // pointer alias. Although this does alias a mutable pointer, we do so by exclusively
        // borrowing the given mutable reference.
        unsafe { from_raw_parts_mut(self as *mut Self as *mut u8, size_of::<Self>()) }
    }
}
