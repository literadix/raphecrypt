//! Minimal WebAssembly ABI for the static single-page app.
//!
//! The exports intentionally avoid `wasm-bindgen` so the browser can load the
//! compiled `.wasm` directly. JavaScript passes UTF-8 strings through exported
//! memory using `raphecrypt_alloc`, then receives UTF-8 result buffers as a
//! packed `(ptr, len)` pair.

use std::{cell::RefCell, slice, str};

use crate::{processing, scan};

const WASM_RANDOM_LEN: usize = 40;

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

#[unsafe(no_mangle)]
pub extern "C" fn raphecrypt_alloc(len: usize) -> *mut u8 {
    let mut buffer = Vec::with_capacity(len);
    let ptr = buffer.as_mut_ptr();
    std::mem::forget(buffer);
    ptr
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn raphecrypt_dealloc(ptr: *mut u8, capacity: usize) {
    if !ptr.is_null() && capacity > 0 {
        unsafe {
            drop(Vec::from_raw_parts(ptr, 0, capacity));
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn raphecrypt_free_result(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        unsafe {
            let slice = std::ptr::slice_from_raw_parts_mut(ptr, len);
            drop(Box::from_raw(slice));
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn raphecrypt_encode(
    visible_ptr: *const u8,
    visible_len: usize,
    hidden_ptr: *const u8,
    hidden_len: usize,
    password_ptr: *const u8,
    password_len: usize,
    random_ptr: *const u8,
    random_len: usize,
) -> u64 {
    let result = (|| {
        let visible = unsafe { read_utf8(visible_ptr, visible_len) }?;
        let hidden = unsafe { read_utf8(hidden_ptr, hidden_len) }?;
        let password = unsafe { read_optional_utf8(password_ptr, password_len) }?;
        let random = unsafe { read_bytes(random_ptr, random_len) };

        if password.is_some() && random.len() != WASM_RANDOM_LEN {
            return Err("browser random bytes were not provided".to_owned());
        }

        let payload = processing::create_hidden_payload_with_random(hidden, password, random)
            .map_err(|error| error.to_string())?;

        Ok(processing::process_payload(visible, &payload))
    })();

    finish(result)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn raphecrypt_decode(
    input_ptr: *const u8,
    input_len: usize,
    password_ptr: *const u8,
    password_len: usize,
) -> u64 {
    let result = (|| {
        let input = unsafe { read_utf8(input_ptr, input_len) }?;
        let password = unsafe { read_optional_utf8(password_ptr, password_len) }?;

        processing::extract_hidden_text(input, password).map_err(|_| "decode failed".to_owned())
    })();

    finish(result)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn raphecrypt_scan(input_ptr: *const u8, input_len: usize) -> u64 {
    let result = (|| {
        let input = unsafe { read_utf8(input_ptr, input_len) }?;
        let report = scan::scan_text(input);

        Ok(scan::format_scan_report(&report))
    })();

    finish(result)
}

#[unsafe(no_mangle)]
pub extern "C" fn raphecrypt_last_error() -> u64 {
    let error = LAST_ERROR
        .with(|last_error| last_error.borrow().clone())
        .unwrap_or_else(|| "unknown error".to_owned());

    leak_string(error)
}

unsafe fn read_utf8<'a>(ptr: *const u8, len: usize) -> Result<&'a str, String> {
    let bytes = unsafe { read_bytes(ptr, len) };

    str::from_utf8(bytes).map_err(|_| "input is not valid UTF-8".to_owned())
}

unsafe fn read_optional_utf8<'a>(ptr: *const u8, len: usize) -> Result<Option<&'a str>, String> {
    if len == 0 {
        Ok(None)
    } else {
        unsafe { read_utf8(ptr, len) }.map(Some)
    }
}

unsafe fn read_bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(ptr, len) }
    }
}

fn finish(result: Result<String, String>) -> u64 {
    match result {
        Ok(output) => {
            LAST_ERROR.with(|last_error| *last_error.borrow_mut() = None);
            leak_string(output)
        }
        Err(error) => {
            LAST_ERROR.with(|last_error| *last_error.borrow_mut() = Some(error));
            0
        }
    }
}

fn leak_string(output: String) -> u64 {
    let bytes = output.into_bytes();
    let len = bytes.len();

    if len == 0 {
        return pack_ptr_len(std::ptr::null_mut(), 0);
    }

    let boxed = bytes.into_boxed_slice();
    let ptr = Box::into_raw(boxed) as *mut u8;

    pack_ptr_len(ptr, len)
}

fn pack_ptr_len(ptr: *mut u8, len: usize) -> u64 {
    ((ptr as u64) << 32) | len as u64
}
