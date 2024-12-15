use core::{
    cell::UnsafeCell,
    ffi::{c_uint, c_void},
    ptr::null_mut,
    sync::atomic::{AtomicBool, Ordering},
};

use spin::RwLock;

use crate::{
    define_indirect_syscall, resolve_indirect_syscalls, run_syscall,
    win32::{
        def::{ClientId, ObjectAttributes, UnicodeString},
        ldrapi::{ldr_function, ldr_module},
    },
};

use super::def::nt_current_teb;

/// Retrieves a handle to the current process.
///
/// # Returns
///
/// A handle to the current process.
pub const fn nt_current_process() -> *mut c_void {
    -1isize as *mut c_void
}

/// Retrieves a handle to the current thread.
///
/// # Returns
///
/// A handle to the current thread.
pub const fn nt_current_thread() -> *mut c_void {
    -2isize as *mut c_void
}

/// Gets the last error value for the current thread.
///
/// This function retrieves the last error code set in the Thread Environment Block (TEB).
/// It mimics the behavior of the `NtGetLastError` macro in C.
///
/// # Safety
/// This function involves unsafe operations and raw pointers, which require careful handling.
pub unsafe fn nt_get_last_error() -> u32 {
    nt_current_teb().as_ref().unwrap().last_error_value
}

#[allow(dead_code)]
pub trait NtSyscall {
    /// Create a new syscall object
    fn new() -> Self;
    /// The number of the syscall
    fn number(&self) -> u16;
    /// The address of the syscall
    fn address(&self) -> *mut u8;
    /// The hash of the syscall (used for lookup)
    fn hash(&self) -> usize;
}

define_indirect_syscall!(NtClose, 0x40d6e69d);

impl NtClose {
    /// Wrapper function for NtClose to avoid repetitive run_syscall calls.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `handle` A handle to an object. This is a required parameter that must be valid.
    ///   It represents the handle that will be closed by the function.
    ///
    /// # Returns
    ///
    /// * `true` if the operation was successful, `false` otherwise. The function returns an
    ///   NTSTATUS code; however, in this wrapper, the result is simplified to a boolean.
    pub unsafe fn run(&self, handle: *mut c_void) -> i32 {
        run_syscall!(self.number, self.address as usize, handle)
    }
}

define_indirect_syscall!(NtAllocateVirtualMemory, 0xf783b8ec);
define_indirect_syscall!(NtFreeVirtualMemory, 0x2802c609);

define_indirect_syscall!(NtOpenKey, 0x7682ed42);
impl NtOpenKey {
    /// Wrapper for the NtOpenKey
    ///
    /// # Arguments
    ///
    /// * `[out]` - `p_key_handle` A mutable pointer to a handle that will receive the key handle.
    /// * `[in]` - `desired_access` Specifies the desired access rights to the key. This is a
    ///   required parameter and determines the allowed operations on the key.
    /// * `[in]` - `object_attributes` A pointer to an `ObjectAttributes` structure that specifies
    ///   the attributes of the key object.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation, indicating success or failure of the
    pub fn run(
        &self,
        p_key_handle: &mut *mut c_void,
        desired_access: u32,
        object_attributes: &mut ObjectAttributes,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            p_key_handle,
            desired_access,
            object_attributes as *mut _ as *mut c_void
        )
    }
}

define_indirect_syscall!(NtQueryValueKey, 0x85967123);
impl NtQueryValueKey {
    /// Wrapper for the NtQueryValueKey
    ///
    /// # Arguments
    ///
    /// * `[in]` - `key_handle` A handle to the key.
    /// * `[in]` - `value_name` A pointer to the UnicodeString structure containing the name of the
    ///   value to be queried.
    /// * `[in]` - `key_value_information_class` Specifies the type of information to be returned.
    /// * `[out]` - `key_value_information` A pointer to a buffer that receives the requested
    ///   information.
    /// * `[in]` - `length` The size, in bytes, of the buffer pointed to by the
    ///   `key_value_information` parameter.
    /// * `[out]` - `result_length` A pointer to a variable that receives the size, in bytes, of the
    ///   data returned.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub unsafe fn run(
        &self,
        key_handle: *mut c_void,
        value_name: &UnicodeString,
        key_value_information_class: u32,
        key_value_information: *mut c_void,
        length: u32,
        result_length: &mut u32,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            key_handle,
            value_name as *const _ as usize,
            key_value_information_class,
            key_value_information,
            length,
            result_length as *mut _ as usize
        )
    }
}

define_indirect_syscall!(NtSetValueKey, 0xd9a01639);
impl NtSetValueKey {
    /// Wrapper for the NtSetValueKey
    ///
    /// # Arguments
    ///
    /// * `[in]` - `key_handle` A handle to the key whose value is to be set.
    /// * `[in]` - `value_name` A pointer to a UnicodeString structure that contains the name of the
    ///   value to be set. If this parameter is `None`, the caller is setting the default value for the key.
    /// * `[in]` - `title_index` The title index of the value to be set. This parameter should typically be 0.
    /// * `[in]` - `key_type` A pointer to a variable that specifies the type of data to be written. This parameter
    ///   must be one of the predefined values, such as REG_SZ (string), REG_DWORD (32-bit integer), etc.
    /// * `[in]` - `data` A pointer to a buffer containing the data to be written.
    /// * `[in]` - `length` The size, in bytes, of the data pointed to by the `data` parameter.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub unsafe fn run(
        &self,
        key_handle: *mut c_void,
        value_name: &UnicodeString,
        title_index: u32,
        key_type: u32,
        data: *mut c_void,
        length: u32,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            key_handle,
            value_name as *const _ as usize,
            title_index,
            key_type,
            data,
            length
        )
    }
}

define_indirect_syscall!(NtDeleteValueKey, 0xff70d480);
impl NtDeleteValueKey {
    /// Wrapper for the NtDeleteValueKey syscall.
    ///
    /// Deletes a specified value from a registry key.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `key_handle`: A handle to the registry key containing the value to delete.
    /// * `[in]` - `value_name`: A pointer to a UnicodeString structure specifying the name of the value to delete.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation. A value of 0 indicates success,
    ///   while any other value represents an error.
    pub unsafe fn run(&self, key_handle: *mut c_void, value_name: &UnicodeString) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            key_handle,
            value_name as *const _ as usize
        )
    }
}

define_indirect_syscall!(NtQuerySystemInformation, 0x7bc23928);
impl NtQuerySystemInformation {
    /// Wrapper for the NtQuerySystemInformation
    ///
    /// # Arguments
    ///
    /// * `[in]` - `system_information_class` The system information class to be queried.
    /// * `[out]` - `system_information` A pointer to a buffer that receives the requested
    ///   information.
    /// * `[in]` - `system_information_length` The size, in bytes, of the buffer pointed to by the
    ///   `system_information` parameter.
    /// * `[out, opt]` - `return_length` A pointer to a variable that receives the size, in bytes,
    ///   of the data returned.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub unsafe fn run(
        &self,
        system_information_class: u32,
        system_information: *mut c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            system_information_class,
            system_information,
            system_information_length,
            return_length
        )
    }
}

define_indirect_syscall!(NtOpenProcess, 0x4b82f718);
impl NtOpenProcess {
    /// Wrapper for the NtOpenProcess
    ///
    /// # Arguments
    ///
    /// * `[out]` - `process_handle` A mutable pointer to a handle that will receive the process
    ///   handle.
    /// * `[in]` - `desired_access` The desired access for the process.
    /// * `[in]` - `object_attributes` A pointer to the object attributes structure.
    /// * `[in, opt]` - `client_id` A pointer to the client ID structure.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub unsafe fn run(
        &self,
        process_handle: &mut *mut c_void,
        desired_access: u32,
        object_attributes: &mut ObjectAttributes,
        client_id: *mut ClientId,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            process_handle,
            desired_access,
            object_attributes as *mut _ as *mut c_void,
            client_id as *mut _ as *mut c_void
        )
    }
}

define_indirect_syscall!(NtOpenProcessToken, 0x350dca99);
impl NtOpenProcessToken {
    /// Wrapper for the NtOpenProcessToken
    ///
    /// # Arguments
    ///
    /// * `[in]` - `process_handle` The handle of the process whose token is to be opened.
    /// * `[in]` - `desired_access` The desired access for the token.
    /// * `[out]` - `token_handle` A mutable pointer to a handle that will receive the token handle.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub unsafe fn run(
        &self,
        process_handle: *mut c_void,
        desired_access: u32,
        token_handle: &mut *mut c_void,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            process_handle,
            desired_access,
            token_handle
        )
    }
}

define_indirect_syscall!(NtDuplicateToken, 0x8e160b23);
impl NtDuplicateToken {
    /// Wrapper for the NtOpenProcessToken
    ///
    /// # Arguments
    ///
    /// * `[in]` - `process_handle` The handle of the process whose token is to be opened.
    /// * `[in]` - `desired_access` The desired access for the token.
    /// * `[out]` - `token_handle` A mutable pointer to a handle that will receive the token handle.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub unsafe fn run(
        &self,
        existing_token_handle: *mut c_void,
        desired_access: u32,
        object_attributes: &mut ObjectAttributes,
        effective_level: u8,
        token_type: u32,
        new_token_handle: &mut *mut c_void,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            existing_token_handle,
            desired_access,
            object_attributes as *mut _ as *mut c_void,
            effective_level as c_uint,
            token_type,
            new_token_handle
        )
    }
}

define_indirect_syscall!(NtQueryInformationToken, 0xf371fe4);
impl NtQueryInformationToken {
    /// Wrapper for the NtQueryInformationToken
    ///
    /// # Arguments
    ///
    /// * `[in]` - `token_handle` The handle of the token to be queried.
    /// * `[in]` - `token_information_class` The class of information to be queried.
    /// * `[out]` - `token_information` A pointer to a buffer that receives the requested
    ///   information.
    /// * `[in]` - `token_information_length` The size, in bytes, of the buffer pointed to by the
    ///   `token_information` parameter.
    /// * `[out, opt]` - `return_length` A pointer to a variable that receives the size, in bytes,
    ///   of the data returned.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub unsafe fn run(
        &self,
        token_handle: *mut c_void,
        token_information_class: u32,
        token_information: *mut c_void,
        token_information_length: u32,
        return_length: *mut u32,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            token_handle,
            token_information_class,
            token_information,
            token_information_length,
            return_length
        )
    }
}

define_indirect_syscall!(NtSetInformationThread, 0xc3c03f1);

impl NtSetInformationThread {
    /// Wrapper for the NtSetInformationThread syscall.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `thread_handle` A handle to the thread for which information is to be set.
    /// * `[in]` - `thread_information_class` The class of information to set for the thread.
    /// * `[in]` - `thread_information` A pointer to a buffer containing the information to be set.
    /// * `[in]` - `thread_information_length` The size, in bytes, of the buffer pointed to by the
    ///   `thread_information` parameter.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation, indicating success or failure.
    pub unsafe fn run(
        &self,
        thread_handle: *mut c_void,
        thread_information_class: u32,
        thread_information: *mut c_void,
        thread_information_length: u32,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            thread_handle,
            thread_information_class,
            thread_information,
            thread_information_length
        )
    }
}

define_indirect_syscall!(NtOpenThread, 0x968e0cb1);

impl NtOpenThread {
    /// Wrapper for the NtOpenThread syscall.
    ///
    /// # Arguments
    ///
    /// * `[out]` - `thread_handle` A mutable pointer to a handle that will receive the thread handle.
    /// * `[in]` - `desired_access` The desired access rights for the thread.
    /// * `[in, optional]` - `object_attributes` A pointer to an `ObjectAttributes` structure that specifies
    ///   the attributes for the thread object. This parameter can be NULL.
    /// * `[in, optional]` - `client_id` A pointer to a `CLIENT_ID` structure that specifies the thread's
    ///   client ID. This parameter can be NULL.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation, indicating success or failure.
    pub unsafe fn run(
        &self,
        thread_handle: &mut *mut c_void,
        desired_access: u32,
        object_attributes: *mut ObjectAttributes,
        client_id: *mut ClientId,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            thread_handle,
            desired_access,
            object_attributes as *mut _ as *mut c_void,
            client_id as *mut _ as *mut c_void
        )
    }
}

define_indirect_syscall!(NtOpenThreadToken, 0x803347d2);

impl NtOpenThreadToken {
    /// Wrapper for the NtOpenThreadToken syscall.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `thread_handle` A handle to the thread whose token is to be opened.
    /// * `[in]` - `desired_access` The desired access rights for the token.
    /// * `[in]` - `open_as_self` If TRUE, the access check is performed as if the calling thread
    ///   is the thread being opened.
    /// * `[out]` - `token_handle` A mutable pointer to a handle that will receive the token handle.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation, indicating success or failure.
    pub unsafe fn run(
        &self,
        thread_handle: *mut c_void,
        desired_access: u32,
        open_as_self: u32,
        token_handle: &mut *mut c_void,
    ) -> i32 {
        run_syscall!(
            self.number,
            self.address as usize,
            thread_handle,
            desired_access,
            open_as_self, // Convert bool to u8 for compatibility.
            token_handle
        )
    }
}

/// Type definition for the LdrLoadDll function.
///
/// Loads a DLL into the address space of the calling process.
///
/// # Parameters
/// - `[in, opt]` - `DllPath`: A pointer to a `UNICODE_STRING` that specifies the fully qualified path of the DLL to load. This can be `NULL`, in which case the system searches for the DLL.
/// - `[in, opt]` - `DllCharacteristics`: A pointer to a variable that specifies the DLL characteristics (optional, can be `NULL`).
/// - `[in]` - `DllName`: A `UNICODE_STRING` that specifies the name of the DLL to load.
/// - `[out]` - `DllHandle`: A pointer to a variable that receives the handle to the loaded DLL.
///
/// # Returns
/// - `i32` - The NTSTATUS code of the operation.
type LdrLoadDll = unsafe extern "system" fn(
    DllPath: *mut u16,
    DllCharacteristics: *mut u32,
    DllName: UnicodeString,
    DllHandle: *mut c_void,
) -> i32;

/// Represents the `NTDLL` library and its functions.
pub struct NtDll {
    pub module_base: *mut u8,
    pub ldr_load_dll: LdrLoadDll,
    pub nt_close: NtClose,
    pub nt_allocate_virtual_memory: NtAllocateVirtualMemory,
    pub nt_free_virtual_memory: NtFreeVirtualMemory,
    pub nt_open_key: NtOpenKey,
    pub nt_query_value_key: NtQueryValueKey,
    pub nt_set_value_key: NtSetValueKey,
    pub nt_delete_value_key: NtDeleteValueKey,
    pub nt_open_process: NtOpenProcess,
    pub nt_query_system_information: NtQuerySystemInformation,
    pub nt_open_process_token: NtOpenProcessToken,
    pub nt_duplicate_token: NtDuplicateToken,
    pub nt_query_information_token: NtQueryInformationToken,
    pub nt_set_information_thread: NtSetInformationThread,
    pub nt_open_thread: NtOpenThread,
    pub nt_open_thread_token: NtOpenThreadToken,
}

impl NtDll {
    pub fn new() -> Self {
        NtDll {
            module_base: null_mut(),
            ldr_load_dll: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            nt_close: NtClose::new(),
            nt_allocate_virtual_memory: NtAllocateVirtualMemory::new(),
            nt_free_virtual_memory: NtFreeVirtualMemory::new(),
            nt_open_key: NtOpenKey::new(),
            nt_query_value_key: NtQueryValueKey::new(),
            nt_set_value_key: NtSetValueKey::new(),
            nt_delete_value_key: NtDeleteValueKey::new(),
            nt_open_process: NtOpenProcess::new(),
            nt_query_system_information: NtQuerySystemInformation::new(),
            nt_open_process_token: NtOpenProcessToken::new(),
            nt_duplicate_token: NtDuplicateToken::new(),
            nt_query_information_token: NtQueryInformationToken::new(),
            nt_set_information_thread: NtSetInformationThread::new(),
            nt_open_thread: NtOpenThread::new(),
            nt_open_thread_token: NtOpenThreadToken::new(),
        }
    }
}

/// Atomic flag to ensure initialization happens only once.
static INIT_NTDLL: AtomicBool = AtomicBool::new(false);

/// Global mutable instance of the ntdll.
pub static mut NTDLL: RwLock<UnsafeCell<Option<NtDll>>> = RwLock::new(UnsafeCell::new(None));

/// Returns a static reference to the `NtDll` instance, ensuring it is initialized before use.
pub unsafe fn ntdll() -> &'static NtDll {
    ensure_initialized();
    let lock = NTDLL.read();
    (*lock.get()).as_ref().unwrap()
}

/// Ensures the `NtDll` library is initialized before any function pointers are used.
unsafe fn ensure_initialized() {
    if !INIT_NTDLL.load(Ordering::Acquire) {
        init_ntdll_funcs();
    }
}

/// Initializes the `NtDll` library by loading `ntdll.dll` and resolving function pointers.
pub unsafe fn init_ntdll_funcs() {
    // Check if initialization has already occurred.
    if !INIT_NTDLL.load(Ordering::Acquire) {
        let mut ntdll = NtDll::new();

        ntdll.module_base = ldr_module(0x1edab0ed);

        // Resolve LdrLoadDll
        let ldr_load_dll_addr = ldr_function(ntdll.module_base, 0x9e456a43);
        ntdll.ldr_load_dll = core::mem::transmute(ldr_load_dll_addr);

        resolve_indirect_syscalls!(
            ntdll.module_base,
            ntdll.nt_close,
            ntdll.nt_allocate_virtual_memory,
            ntdll.nt_free_virtual_memory,
            ntdll.nt_open_key,
            ntdll.nt_query_value_key,
            ntdll.nt_set_value_key,
            ntdll.nt_delete_value_key,
            ntdll.nt_open_process,
            ntdll.nt_query_system_information,
            ntdll.nt_open_process_token,
            ntdll.nt_duplicate_token,
            ntdll.nt_query_information_token,
            ntdll.nt_set_information_thread,
            ntdll.nt_open_thread,
            ntdll.nt_open_thread_token
        );

        let ntdll_lock = NTDLL.write();
        *ntdll_lock.get() = Some(ntdll);

        // Set the initialization flag to true.
        INIT_NTDLL.store(true, Ordering::Release);
    }
}
