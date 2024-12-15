use core::arch::global_asm;

extern "C" {
    // Declaration of an external syscall function with a variadic argument list
    pub fn isyscall(ssn: u16, addr: usize, n_args: u32, ...) -> i32;
}

/// Macro to define a syscall structure and its associated implementations.
///
/// This macro generates a struct with the given name and a specified hash value.
/// It also implements the `NtSyscall` trait, `Send`, `Sync`, and `Default` traits for the generated
/// struct.
///
/// # Arguments
///
/// * `$name` - The identifier for the syscall struct.
/// * `$hash` - The hash value associated with the syscall.
///
/// # Generated Struct
///
/// The generated struct will have the following fields:
/// * `number` - A `u16` representing the syscall number.
/// * `address` - A mutable pointer to `u8` representing the address of the syscall.
/// * `hash` - A `usize` representing the hash value of the syscall.
#[macro_export]
macro_rules! define_indirect_syscall {
    ($name:ident, $hash:expr) => {
        pub struct $name {
            pub number: u16,
            pub address: *mut u8,
            pub hash: usize,
        }

        impl NtSyscall for $name {
            fn new() -> Self {
                Self {
                    number: 0,
                    address: core::ptr::null_mut(),
                    hash: $hash,
                }
            }

            fn number(&self) -> u16 {
                self.number
            }

            fn address(&self) -> *mut u8 {
                self.address
            }

            fn hash(&self) -> usize {
                self.hash
            }
        }

        // Safety: This is safe because the struct $name does not contain any non-thread-safe data.
        unsafe impl Send for $name {}
        // Safety: This is safe because the struct $name does not contain any non-thread-safe data.
        unsafe impl Sync for $name {}

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

#[macro_export]
macro_rules! resolve_indirect_syscalls {
    ($module_base:expr, $( $syscall:expr ),* ) => {
        $(
            // Resolve the address of the syscall using the module base and hash.
            $syscall.address = $crate::win32::ldrapi::ldr_function($module_base, $syscall.hash);

            // Extract the syscall number from the resolved address.
            $syscall.number = $crate::win32::gate::get_ssn($syscall.address);
        )*
    };
}

#[macro_export]
macro_rules! resolve_direct_syscalls {
    ($module_base:expr, [ $( ($syscall:expr, $hash:expr, $f:ty) ),* ]) => {
        $(
            // Resolve the address of the API call using the provided hash
            let apicall_addr = $crate::win32::ldrapi::ldr_function($module_base, $hash);

            // Cast the resolved address to the specified function signature and assign it
            $syscall = Some(core::mem::transmute::<*mut u8, $f>(apicall_addr));
        )*
    };
}

#[cfg(target_arch = "x86_64")]
#[macro_export]
macro_rules! run_syscall {
    ($ssn:expr, $addr:expr, $($y:expr), +) => {
        {
            let mut cnt: u32 = 0;

            // Count the number of arguments passed
            $(
                let _ = $y;
                cnt += 1;
            )+

            // Perform the syscall with the given number, address (offset by 0x12),
            // argument count, and the arguments
            unsafe { $crate::win32::gate::isyscall($ssn, $addr + 0x12, cnt, $($y), +) }
        }
    }
}

const UP: isize = -32; // Constant for upward memory search
const DOWN: usize = 32; // Constant for downward memory search

pub unsafe fn get_ssn(address: *mut u8) -> u16 {
    if address.is_null() {
        return 0;
    }

    // Hell's Gate: Check if the bytes match a typical syscall instruction sequence
    // mov r10, rcx; mov rcx, <syscall>
    if address.read() == 0x4c
        && address.add(1).read() == 0x8b
        && address.add(2).read() == 0xd1
        && address.add(3).read() == 0xb8
        && address.add(6).read() == 0x00
        && address.add(7).read() == 0x00
    {
        let high = address.add(5).read() as u16;
        let low = address.add(4).read() as u16;
        return (high << 8) | low;
    }

    // Halo's Gate: Check if the syscall is hooked and attempt to locate a clean syscall
    if address.read() == 0xe9 {
        for idx in 1..500 {
            // Check downwards for a clean syscall instruction
            if address.add(idx * DOWN).read() == 0x4c
                && address.add(1 + idx * DOWN).read() == 0x8b
                && address.add(2 + idx * DOWN).read() == 0xd1
                && address.add(3 + idx * DOWN).read() == 0xb8
                && address.add(6 + idx * DOWN).read() == 0x00
                && address.add(7 + idx * DOWN).read() == 0x00
            {
                let high = address.add(5 + idx * DOWN).read() as u16;
                let low = address.add(4 + idx * DOWN).read() as u16;
                return (high << 8) | (low.wrapping_sub(idx as u16));
            }

            // Check upwards for a clean syscall instruction
            if address.offset(idx as isize * UP).read() == 0x4c
                && address.offset(1 + idx as isize * UP).read() == 0x8b
                && address.offset(2 + idx as isize * UP).read() == 0xd1
                && address.offset(3 + idx as isize * UP).read() == 0xb8
                && address.offset(6 + idx as isize * UP).read() == 0x00
                && address.offset(7 + idx as isize * UP).read() == 0x00
            {
                let high = address.offset(5 + idx as isize * UP).read() as u16;
                let low = address.offset(4 + idx as isize * UP).read() as u16;
                return (high << 8) | (low.wrapping_add(idx as u16));
            }
        }
    }

    // Tartarus' Gate: Another method to bypass hooked syscalls
    if address.add(3).read() == 0xe9 {
        for idx in 1..500 {
            // Check downwards for a clean syscall instruction
            if address.add(idx * DOWN).read() == 0x4c
                && address.add(1 + idx * DOWN).read() == 0x8b
                && address.add(2 + idx * DOWN).read() == 0xd1
                && address.add(3 + idx * DOWN).read() == 0xb8
                && address.add(6 + idx * DOWN).read() == 0x00
                && address.add(7 + idx * DOWN).read() == 0x00
            {
                let high = address.add(5 + idx * DOWN).read() as u16;
                let low = address.add(4 + idx * DOWN).read() as u16;
                return (high << 8) | (low.wrapping_sub(idx as u16));
            }

            // Check upwards for a clean syscall instruction
            if address.offset(idx as isize * UP).read() == 0x4c
                && address.offset(1 + idx as isize * UP).read() == 0x8b
                && address.offset(2 + idx as isize * UP).read() == 0xd1
                && address.offset(3 + idx as isize * UP).read() == 0xb8
                && address.offset(6 + idx as isize * UP).read() == 0x00
                && address.offset(7 + idx as isize * UP).read() == 0x00
            {
                let high = address.offset(5 + idx as isize * UP).read() as u16;
                let low = address.offset(4 + idx as isize * UP).read() as u16;
                return (high << 8) | (low.wrapping_add(idx as u16));
            }
        }
    }

    0
}

#[cfg(target_arch = "x86_64")]
global_asm!(
    "
.globl _start
.globl isyscall

.section .text

_start:
    push  rsi
    mov   rsi, rsp
    and   rsp, 0xFFFFFFFFFFFFFFF0
    sub   rsp, 0x20
    call  go
    mov   rsp, rsi
    pop   rsi
    ret

isyscall:
    mov [rsp - 0x8],  rsi
    mov [rsp - 0x10], rdi
    mov [rsp - 0x18], r12

    xor r10, r10			
    mov rax, rcx			
    mov r10, rax

    mov eax, ecx

    mov r12, rdx
    mov rcx, r8

    mov r10, r9
    mov rdx,  [rsp + 0x28]
    mov r8,   [rsp + 0x30]
    mov r9,   [rsp + 0x38]

    sub rcx, 0x4
    jle skip

    lea rsi,  [rsp + 0x40]
    lea rdi,  [rsp + 0x28]

    rep movsq
skip:
    mov rcx, r12

    mov rsi, [rsp - 0x8]
    mov rdi, [rsp - 0x10]
    mov r12, [rsp - 0x18]

    jmp rcx
"
);

extern "C" {
    fn _start();
}
