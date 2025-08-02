#![no_std]
#![no_main]

use aya_ebpf::bindings::BPF_F_USER_STACK;
use aya_ebpf::{cty::c_char, helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_smp_processor_id}, macros::{map, perf_event}, maps::{PerCpuArray, RingBuf, StackTrace}, programs::PerfEventContext};
use larkspur_common::Sample;


#[map]
static SAMPLES: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static STACKS: StackTrace = StackTrace::with_max_entries(16384, 0);

#[map]
static USTACKS: StackTrace = StackTrace::with_max_entries(16384, 0);

#[map]
static BUF: PerCpuArray<Sample> = PerCpuArray::with_max_entries(1, 0);

#[perf_event]
pub fn larkspur(_ctx: PerfEventContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let cpu = unsafe { bpf_get_smp_processor_id() };

    let sample = match BUF.get_ptr_mut(0) {
        Some(p) => p,
        None => return 1
    };

    unsafe {
        (*sample).pid = pid;
        (*sample).cpu = cpu;
        let _ = bpf_get_current_comm().map(|b| {
            for (i, &v) in b.iter().enumerate() {
                (*sample).comm[i] = v as c_char;
            }
        });
    }

    let kstack_id = unsafe { STACKS.get_stackid(&_ctx, 0).unwrap_or(-1) };
    let ustack_id = unsafe { USTACKS.get_stackid(&_ctx, BPF_F_USER_STACK as u64).unwrap_or(-1) };

    unsafe {
        (*sample).kstack_id = kstack_id;
        (*sample).ustack_id = ustack_id;
    }

    if let Some(mut entry) = SAMPLES.reserve::<Sample>(0) {
        unsafe { entry.write(*sample); }
        entry.submit(0);
    }

    0
}


#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
