use core::arch::asm;
use core::ffi::{c_long, c_ulong, c_void};
use core::ptr;

use alloc::format;
use alloc::string::String;

use crate::utils::string_length_w;

pub type HANDLE = *mut c_void;

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
pub const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // "PE\0\0"

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

impl UnicodeString {
    pub fn new() -> Self {
        UnicodeString {
            length: 0,
            maximum_length: 0,
            buffer: ptr::null_mut(),
        }
    }

    // RtlInitUnicodeString
    pub fn init(&mut self, source_string: *const u16) {
        if !source_string.is_null() {
            let dest_size = string_length_w(source_string) * 2;
            self.length = dest_size as u16;
            self.maximum_length = (dest_size + 2) as u16;
            self.buffer = source_string as *mut u16;
        } else {
            self.length = 0;
            self.maximum_length = 0;
            self.buffer = ptr::null_mut();
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SectionPointer {
    pub section_pointer: *mut c_void,
    pub check_sum: c_ulong,
}

#[repr(C)]
pub union HashLinksOrSectionPointer {
    pub hash_links: ListEntry,
    pub section_pointer: SectionPointer,
}

#[repr(C)]
pub union TimeDateStampOrLoadedImports {
    pub time_date_stamp: c_ulong,
    pub loaded_imports: *mut c_void,
}

#[repr(C)]
pub struct LoaderDataTableEntry {
    pub in_load_order_links: ListEntry,
    pub in_memory_order_links: ListEntry,
    pub in_initialization_order_links: ListEntry,
    pub dll_base: *mut c_void,
    pub entry_point: *mut c_void,
    pub size_of_image: c_ulong,
    pub full_dll_name: UnicodeString,
    pub base_dll_name: UnicodeString,
    pub flags: c_ulong,
    pub load_count: i16,
    pub tls_index: i16,
    pub hash_links_or_section_pointer: HashLinksOrSectionPointer,
    pub time_date_stamp_or_loaded_imports: TimeDateStampOrLoadedImports,
    pub entry_point_activation_context: *mut c_void,
    pub patch_information: *mut c_void,
    pub forwarder_links: ListEntry,
    pub service_tag_links: ListEntry,
    pub static_links: ListEntry,
}

#[repr(C)]
pub struct PebLoaderData {
    pub length: c_ulong,
    pub initialized: c_ulong,
    pub ss_handle: *mut c_void,
    pub in_load_order_module_list: ListEntry,
    pub in_memory_order_module_list: ListEntry,
    pub in_initialization_order_module_list: ListEntry,
}

#[repr(C)]
pub struct PEB {
    pub inherited_address_space: bool,
    pub read_image_file_exec_options: bool,
    pub being_debugged: bool,
    pub spare: bool,
    pub mutant: *mut c_void,
    pub image_base: *mut c_void,
    pub loader_data: *const PebLoaderData,
    pub process_parameters: *const RtlUserProcessParameters,
    pub sub_system_data: *mut c_void,
    pub process_heap: *mut c_void,
    pub fast_peb_lock: *mut c_void,
    pub fast_peb_lock_routine: *mut c_void,
    pub fast_peb_unlock_routine: *mut c_void,
    pub environment_update_count: c_ulong,
    pub kernel_callback_table: *const *mut c_void,
    pub event_log_section: *mut c_void,
    pub event_log: *mut c_void,
    pub free_list: *mut c_void,
    pub tls_expansion_counter: c_ulong,
    pub tls_bitmap: *mut c_void,
    pub tls_bitmap_bits: [c_ulong; 2],
    pub read_only_shared_memory_base: *mut c_void,
    pub read_only_shared_memory_heap: *mut c_void,
    pub read_only_static_server_data: *const *mut c_void,
    pub ansi_code_page_data: *mut c_void,
    pub oem_code_page_data: *mut c_void,
    pub unicode_case_table_data: *mut c_void,
    pub number_of_processors: c_ulong,
    pub nt_global_flag: c_ulong,
    pub spare_2: [u8; 4],
    pub critical_section_timeout: i64,
    pub heap_segment_reserve: c_ulong,
    pub heap_segment_commit: c_ulong,
    pub heap_de_commit_total_free_threshold: c_ulong,
    pub heap_de_commit_free_block_threshold: c_ulong,
    pub number_of_heaps: c_ulong,
    pub maximum_number_of_heaps: c_ulong,
    pub process_heaps: *const *const *mut c_void,
    pub gdi_shared_handle_table: *mut c_void,
    pub process_starter_helper: *mut c_void,
    pub gdi_dc_attribute_list: *mut c_void,
    pub loader_lock: *mut c_void,
    pub os_major_version: c_ulong,
    pub os_minor_version: c_ulong,
    pub os_build_number: c_ulong,
    pub os_platform_id: c_ulong,
    pub image_sub_system: c_ulong,
    pub image_sub_system_major_version: c_ulong,
    pub image_sub_system_minor_version: c_ulong,
    pub gdi_handle_buffer: [c_ulong; 22],
    pub post_process_init_routine: c_ulong,
    pub tls_expansion_bitmap: c_ulong,
    pub tls_expansion_bitmap_bits: [u8; 80],
    pub session_id: c_ulong,
}

#[repr(C)]
pub struct RtlUserProcessParameters {
    pub maximum_length: u32,
    pub length: u32,
    pub flags: u32,
    pub debug_flags: u32,
    pub console_handle: *mut c_void,
    pub console_flags: u32,
    pub standard_input: *mut c_void,
    pub standard_output: *mut c_void,
    pub standard_error: *mut c_void,
    pub current_directory_path: UnicodeString,
    pub current_directory_handle: *mut c_void,
    pub dll_path: UnicodeString,
    pub image_path_name: UnicodeString,
    pub command_line: UnicodeString,
    pub environment: *mut c_void,
    pub starting_x: u32,
    pub starting_y: u32,
    pub count_x: u32,
    pub count_y: u32,
    pub count_chars_x: u32,
    pub count_chars_y: u32,
    pub fill_attribute: u32,
    pub window_flags: u32,
    pub show_window_flags: u32,
    pub window_title: UnicodeString,
    pub desktop_info: UnicodeString,
    pub shell_info: UnicodeString,
    pub runtime_data: UnicodeString,
    pub current_directories: [UnicodeString; 32],
    pub environment_size: u32,
    pub environment_version: u32,
    pub package_dependency_data: *mut c_void,
    pub process_group_id: u32,
    pub loader_threads: u32,
}

#[repr(C)]
pub struct ImageDosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[repr(C)]
pub struct ImageExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct ImageNtHeaders {
    pub signature: u32,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader64,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

#[cfg(target_arch = "x86_64")]
pub fn find_peb() -> *mut PEB {
    let peb_ptr: *mut PEB;
    unsafe {
        asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb_ptr
        );
    }
    peb_ptr
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LargeInteger {
    pub low_part: u32,
    pub high_part: i32,
}

#[repr(C)]
pub struct ClientId {
    pub unique_process: *mut c_void,
    pub unique_thread: *mut c_void,
}

impl ClientId {
    pub fn new() -> Self {
        ClientId {
            unique_process: core::ptr::null_mut(),
            unique_thread: core::ptr::null_mut(),
        }
    }
}

#[repr(C)]
pub struct ObjectAttributes {
    pub length: c_ulong,
    pub root_directory: *mut c_void,
    pub object_name: *mut UnicodeString,
    pub attributes: c_ulong,
    pub security_descriptor: *mut c_void,
    pub security_quality_of_service: *mut c_void,
}

impl ObjectAttributes {
    pub fn new() -> Self {
        ObjectAttributes {
            length: 0,
            root_directory: ptr::null_mut(),
            object_name: ptr::null_mut(),
            attributes: 0,
            security_descriptor: ptr::null_mut(),
            security_quality_of_service: ptr::null_mut(),
        }
    }

    //InitializeObjectAttributes
    pub fn initialize(
        p: &mut ObjectAttributes,
        n: *mut UnicodeString,
        a: c_ulong,
        r: *mut c_void,
        s: *mut c_void,
    ) {
        p.length = core::mem::size_of::<ObjectAttributes>() as c_ulong;
        p.root_directory = r;
        p.attributes = a;
        p.object_name = n;
        p.security_descriptor = s;
        p.security_quality_of_service = ptr::null_mut();
    }
}

#[repr(C)]
pub struct SystemProcessInformation {
    pub next_entry_offset: u32,
    pub number_of_threads: u32,
    pub working_set_private_size: LargeInteger,
    pub hard_fault_count: u32,
    pub number_of_threads_high_watermark: u32,
    pub cycle_time: u64,
    pub create_time: LargeInteger,
    pub user_time: LargeInteger,
    pub kernel_time: LargeInteger,
    pub image_name: UnicodeString,
    pub base_priority: i32,
    pub unique_process_id: *mut c_void,
    pub inherited_from_unique_process_id: *mut c_void,
    pub handle_count: u32,
    pub session_id: u32,
    pub unique_process_key: usize,
    pub peak_virtual_size: usize,
    pub virtual_size: usize,
    pub page_fault_count: u32,
    pub peak_working_set_size: usize,
    pub working_set_size: usize,
    pub quota_peak_paged_pool_usage: usize,
    pub quota_paged_pool_usage: usize,
    pub quota_peak_non_paged_pool_usage: usize,
    pub quota_non_paged_pool_usage: usize,
    pub pagefile_usage: usize,
    pub peak_pagefile_usage: usize,
    pub private_page_count: usize,
    pub read_operation_count: LargeInteger,
    pub write_operation_count: LargeInteger,
    pub other_operation_count: LargeInteger,
    pub read_transfer_count: LargeInteger,
    pub write_transfer_count: LargeInteger,
    pub other_transfer_count: LargeInteger,
    pub threads: [SystemThreadInformation; 1],
}

#[repr(C)]
pub struct SystemThreadInformation {
    pub kernel_time: LargeInteger,
    pub user_time: LargeInteger,
    pub create_time: LargeInteger,
    pub wait_time: u32,
    pub start_address: *mut c_void,
    pub client_id: ClientId,
    pub priority: c_long,
    pub base_priority: c_long,
    pub context_switches: u32,
    pub thread_state: u32,
    pub wait_reason: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SecurityQualityOfService {
    pub length: u32,
    pub impersonation_level: u32,
    pub context_tracking_mode: u8,
    pub effective_only: u8,
}

pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

#[allow(non_snake_case)]
pub fn NT_STATUS(status: i32) -> String {
    match status {
        STATUS_SUCCESS => format!("STATUS_SUCCESS [0x{:08X}]", status),
        STATUS_BUFFER_OVERFLOW => format!("STATUS_BUFFER_OVERFLOW [0x{:08X}]", status),
        STATUS_BUFFER_TOO_SMALL => format!("STATUS_BUFFER_TOO_SMALL [0x{:08X}]", status),
        STATUS_OBJECT_NAME_NOT_FOUND => format!("STATUS_OBJECT_NAME_NOT_FOUND [0x{:08X}]", status),
        STATUS_INFO_LENGTH_MISMATCH => format!("STATUS_INFO_LENGTH_MISMATCH [0x{:08X}]", status),
        STATUS_ACCESS_VIOLATION => format!("STATUS_ACCESS_VIOLATION [0x{:08X}]", status),
        STATUS_ACCESS_DENIED => format!("STATUS_ACCESS_DENIED [0x{:08X}]", status),
        STATUS_INVALID_HANDLE => format!("STATUS_INVALID_HANDLE [0x{:08X}]", status),
        STATUS_INSUFFICIENT_RESOURCES => {
            format!("STATUS_INSUFFICIENT_RESOURCES [0x{:08X}]", status)
        }
        STATUS_NOT_IMPLEMENTED => format!("STATUS_NOT_IMPLEMENTED [0x{:08X}]", status),
        STATUS_INVALID_PARAMETER => format!("STATUS_INVALID_PARAMETER [0x{:08X}]", status),
        STATUS_CONFLICTING_ADDRESSES => format!("STATUS_CONFLICTING_ADDRESSES [0x{:08X}]", status),
        STATUS_PRIVILEGE_NOT_HELD => format!("STATUS_PRIVILEGE_NOT_HELD [0x{:08X}]", status),
        STATUS_MEMORY_NOT_ALLOCATED => format!("STATUS_MEMORY_NOT_ALLOCATED [0x{:08X}]", status),
        STATUS_INVALID_PAGE_PROTECTION => {
            format!("STATUS_INVALID_PAGE_PROTECTION [0x{:08X}]", status)
        }
        STATUS_ILLEGAL_INSTRUCTION => format!("STATUS_ILLEGAL_INSTRUCTION [0x{:08X}]", status),
        STATUS_INTEGER_DIVIDE_BY_ZERO => {
            format!("STATUS_INTEGER_DIVIDE_BY_ZERO [0x{:08X}]", status)
        }
        STATUS_DLL_NOT_FOUND => format!("STATUS_DLL_NOT_FOUND [0x{:08X}]", status),
        STATUS_DLL_INIT_FAILED => format!("STATUS_DLL_INIT_FAILED [0x{:08X}]", status),
        STATUS_NO_SUCH_FILE => format!("STATUS_NO_SUCH_FILE [0x{:08X}]", status),
        STATUS_INVALID_DEVICE_REQUEST => {
            format!("STATUS_INVALID_DEVICE_REQUEST [0x{:08X}]", status)
        }
        STATUS_NOT_FOUND => format!("STATUS_NOT_FOUND [0x{:08X}]", status),
        STATUS_DATATYPE_MISALIGNMENT => format!("STATUS_DATATYPE_MISALIGNMENT [0x{:08X}]", status),
        STATUS_OBJECT_NAME_INVALID => format!("STATUS_OBJECT_NAME_INVALID [0x{:08X}]", status),
        STATUS_NAME_TOO_LONG => format!("STATUS_NAME_TOO_LONG [0x{:08X}]", status),
        STATUS_OBJECT_PATH_SYNTAX_BAD => {
            format!("STATUS_OBJECT_PATH_SYNTAX_BAD [0x{:08X}]", status)
        }
        STATUS_NO_MEMORY => format!("STATUS_NO_MEMORY [0x{:08X}]", status),
        STATUS_END_OF_FILE => format!("STATUS_END_OF_FILE [0x{:08X}]", status),
        STATUS_PENDING => format!("STATUS_PENDING [0x{:08X}]", status),
        STATUS_NO_TOKEN => format!("STATUS_NO_TOKEN [0x{:08X}]", status),
        _ => format!("STATUS_UNKNOWN [0x{:08X}]", status),
    }
}

pub const NT_SUCCESS: fn(i32) -> bool = |status| status >= 0;

pub const STATUS_SUCCESS: i32 = 0;
pub const STATUS_BUFFER_OVERFLOW: i32 = 0x80000005u32 as i32;
pub const STATUS_BUFFER_TOO_SMALL: i32 = 0xc0000023u32 as i32;
pub const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xc0000034u32 as i32;
pub const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xc0000004u32 as i32;
pub const STATUS_ACCESS_VIOLATION: i32 = 0xc0000005u32 as i32;
pub const STATUS_ACCESS_DENIED: i32 = 0xc0000022u32 as i32;
pub const STATUS_INVALID_HANDLE: i32 = 0xc0000008u32 as i32;
pub const STATUS_INSUFFICIENT_RESOURCES: i32 = 0xc000009au32 as i32;
pub const STATUS_NOT_IMPLEMENTED: i32 = 0xc0000002u32 as i32;
pub const STATUS_INVALID_PARAMETER: i32 = 0xc000000du32 as i32;
pub const STATUS_CONFLICTING_ADDRESSES: i32 = 0xc0000018u32 as i32;
pub const STATUS_PRIVILEGE_NOT_HELD: i32 = 0xc0000061u32 as i32;
pub const STATUS_MEMORY_NOT_ALLOCATED: i32 = 0xc00000a0u32 as i32;
pub const STATUS_INVALID_PAGE_PROTECTION: i32 = 0xc0000045u32 as i32;
pub const STATUS_ILLEGAL_INSTRUCTION: i32 = 0xc000001du32 as i32;
pub const STATUS_INTEGER_DIVIDE_BY_ZERO: i32 = 0xc0000094u32 as i32;
pub const STATUS_DLL_NOT_FOUND: i32 = 0xc0000135u32 as i32;
pub const STATUS_DLL_INIT_FAILED: i32 = 0xc0000142u32 as i32;
pub const STATUS_NO_SUCH_FILE: i32 = 0xc000000fu32 as i32;
pub const STATUS_INVALID_DEVICE_REQUEST: i32 = 0xc0000010u32 as i32;
pub const STATUS_NOT_FOUND: i32 = 0xc0000225u32 as i32;
pub const STATUS_DATATYPE_MISALIGNMENT: i32 = 0x80000002u32 as i32;
pub const STATUS_OBJECT_NAME_INVALID: i32 = 0xc0000033u32 as i32;
pub const STATUS_NAME_TOO_LONG: i32 = 0xc0000106u32 as i32;
pub const STATUS_OBJECT_PATH_SYNTAX_BAD: i32 = 0xc000003bu32 as i32;
pub const STATUS_NO_MEMORY: i32 = 0xc0000017u32 as i32;
pub const STATUS_END_OF_FILE: i32 = 0xc0000011u32 as i32;
pub const STATUS_PENDING: i32 = 0x00000103u32 as i32;
pub const STATUS_NO_TOKEN: i32 = 0xC000007Cu32 as i32;

#[repr(C)]
#[derive(PartialEq)]
pub enum TokenType {
    TokenPrimary = 1,
    TokenImpersonation,
}

#[cfg(feature = "threads")]
pub const OBJ_INHERIT: u32 = 0x00000002;

pub const OBJ_CASE_INSENSITIVE: c_ulong = 0x40;

pub const STANDARD_RIGHTS_REQUIRED: u32 = 0x000f0000;

pub const TOKEN_ASSIGN_PRIMARY: u32 = 0x0001;
pub const TOKEN_DUPLICATE: u32 = 0x0002;
pub const TOKEN_IMPERSONATE: u32 = 0x0004;
pub const TOKEN_QUERY: u32 = 0x0008;
pub const TOKEN_QUERY_SOURCE: u32 = 0x0010;
pub const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
pub const TOKEN_ADJUST_GROUPS: u32 = 0x0040;
pub const TOKEN_ADJUST_DEFAULT: u32 = 0x0080;
pub const TOKEN_ADJUST_SESSIONID: u32 = 0x0100;
pub const TOKEN_ALL_ACCESS_P: u32 = STANDARD_RIGHTS_REQUIRED
    | TOKEN_ASSIGN_PRIMARY
    | TOKEN_DUPLICATE
    | TOKEN_IMPERSONATE
    | TOKEN_QUERY
    | TOKEN_QUERY_SOURCE
    | TOKEN_ADJUST_PRIVILEGES
    | TOKEN_ADJUST_GROUPS
    | TOKEN_ADJUST_DEFAULT;
pub const TOKEN_ALL_ACCESS: u32 = TOKEN_ALL_ACCESS_P | TOKEN_ADJUST_SESSIONID;

#[cfg(feature = "threads")]
pub const THREAD_QUERY_INFORMATION: u32 = 0x0040;

#[repr(C)]
#[allow(dead_code)]
pub enum SecurityImpersonationLevel {
    SecurityAnonymous,
    SecurityIdentification,
    SecurityImpersonation,
    SecurityDelegation,
}

#[repr(C)]
pub struct TokenUser {
    pub user: SidAndAttributes,
}

#[repr(C)]
pub struct SidAndAttributes {
    pub sid: *mut c_void,
    pub attributes: u32,
}

#[repr(C)]
pub struct TokenElevation {
    pub token_is_elevated: u32,
}

#[allow(dead_code)]
pub enum TokenInformationClass {
    TokenUser = 1,
    TokenGroups,
    TokenPrivileges,
    TokenOwner,
    TokenPrimaryGroup,
    TokenDefaultDacl,
    TokenSource,
    TokenType,
    TokenImpersonationLevel,
    TokenStatistics,
    TokenRestrictedSids,
    TokenSessionId,
    TokenGroupsAndPrivileges,
    TokenSessionReference,
    TokenSandBoxInert,
    TokenAuditPolicy,
    TokenOrigin,
    TokenElevationType,
    TokenLinkedToken,
    TokenElevation,
    TokenHasRestrictions,
    TokenAccessInformation,
    TokenVirtualizationAllowed,
    TokenVirtualizationEnabled,
    TokenIntegrityLevel,
    TokenUIAccess,
    TokenMandatoryPolicy,
    TokenLogonSid,
    TokenIsAppContainer,
    TokenCapabilities,
    TokenAppContainerSid,
    TokenAppContainerNumber,
    TokenUserClaimAttributes,
    TokenDeviceClaimAttributes,
    TokenRestrictedUserClaimAttributes,
    TokenRestrictedDeviceClaimAttributes,
    TokenDeviceGroups,
    TokenRestrictedDeviceGroups,
    TokenSecurityAttributes,
    TokenIsRestricted,
    TokenProcessTrustLevel,
    TokenPrivateNameSpace,
    TokenSingletonAttributes,
    TokenBnoIsolation,
    MaxTokenInfoClass,
}

pub const STANDARD_RIGHTS_READ: u32 = 0x00020000;
pub const SYNCHRONIZE: u32 = 0x00100000;

pub const KEY_QUERY_VALUE: u32 = 0x0001;
pub const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
pub const KEY_NOTIFY: u32 = 0x0010;
pub const KEY_READ: u32 =
    (STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY) & (!SYNCHRONIZE);

pub const STANDARD_RIGHTS_WRITE: u32 = 0x00020000;
pub const KEY_SET_VALUE: u32 = 0x0002;
pub const KEY_CREATE_SUB_KEY: u32 = 0x0004;

pub const KEY_WRITE: u32 =
    (STANDARD_RIGHTS_WRITE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY) & !SYNCHRONIZE;

#[repr(C)]
pub struct KeyValuePartialInformation {
    pub title_index: u32,
    pub data_type: u32,
    pub data_length: u32,
    pub data: [u8; 1],
}

#[repr(C)]
pub struct NtTib {
    pub exception_list: *mut c_void,
    pub stack_base: *mut c_void,
    pub stack_limit: *mut c_void,
    pub sub_system_tib: *mut c_void,
    pub fiber_data: *mut c_void,
    pub arbitrary_user_pointer: *mut c_void,
    pub self_: *mut NtTib,
}

// Safety: NtTib is a pointer to itself, so it's safe to share across threads
unsafe impl Sync for NtTib {}
// Safety: NtTib is a pointer to itself, so it's safe to send across threads
unsafe impl Send for NtTib {}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct TEB {
    pub nt_tib: NtTib,
    pub environment_pointer: *mut c_void,
    pub client_id: ClientId,
    pub active_rpc_handle: *mut c_void,
    pub thread_local_storage_pointer: *mut c_void,
    pub process_environment_block: *mut PEB,
    pub last_error_value: u32,
    pub count_of_owned_critical_sections: u32,
    pub csr_client_thread: *mut c_void,
    pub win32_thread_info: *mut c_void,
    pub user32_reserved: [u32; 26],
    pub user_reserved: [u32; 5],
    pub wow64_reserved: *mut c_void,
    pub current_locale: u32,
    pub fp_software_status_register: u32,
    pub system_reserved1: [*mut c_void; 54],
    pub exception_code: u32,
    pub activation_context_stack_pointer: *mut c_void,
    pub spare_bytes: [u8; 24],
    pub tx_fs_context: u32,
    pub gdi_tcell_buffer: *mut c_void,
    pub gdi_prev_spare_tcell: u32,
    pub gdi_prev_spare_tx: u32,
    pub gdi_batch_count: u32,
    pub spare_stack_array: [u32; 0x200],
    pub spare1: [u8; 40],
    pub x64_spare2: [u32; 0x3d],
    pub x64_spare3: [u32; 0x3d],
    pub tx_fb_context: u32,
    pub gdi_last_spare_tcell: u32,
    pub gdi_last_spare_tx: u32,
    pub gdi_last_spare_stack_array: [u32; 0x200],
}

unsafe impl Sync for TEB {}
unsafe impl Send for TEB {}

/// Find the Thread Environment Block (TEB) of the current process on x86_64
#[cfg(target_arch = "x86_64")]
pub fn nt_current_teb() -> *mut TEB {
    let teb_ptr: *mut TEB;
    unsafe {
        asm!(
            "mov {}, gs:[0x30]",
            out(reg) teb_ptr
        );
    }
    teb_ptr
}
