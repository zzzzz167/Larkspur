#![no_std]
#![no_main]

use aya_ebpf::{macros::{map, raw_tracepoint},
               maps::{HashMap, StackTrace, RingBuf},
               programs::RawTracePointContext,
               bindings::BPF_F_USER_STACK,
               helpers::{bpf_probe_read_kernel, bpf_ktime_get_ns},
               EbpfContext};
use larkspur_common::{OffCpuSample, TaskIdent};

#[repr(C)]
struct SchedSwitch {
    common_type:   u16,
    common_flags:  u8,
    common_preempt_count: u8,
    common_pid:    i32,

    prev_comm: [u8; 16],
    prev_pid:  i32,
    prev_prio: i32,
    prev_state: i64,

    next_comm: [u8; 16],
    next_pid:  i32,
    next_prio: i32,
}

#[map]
static START: HashMap<TaskIdent, u64> = HashMap::with_max_entries(10240, 0);

#[map]
static KSTACK: StackTrace = StackTrace::with_max_entries(16384, 0);
#[map]
static USTACK: StackTrace = StackTrace::with_max_entries(16384, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[raw_tracepoint(tracepoint="sched_switch")]
pub fn off_cpu_trace(ctx: RawTracePointContext) -> u32{

    let _rec = ctx.as_ptr() as *const SchedSwitch;

    let mut data: SchedSwitch = unsafe { core::mem::zeroed() };

    let _ = unsafe {
        bpf_probe_read_kernel(&mut data as *mut _ as *mut u8)
    };

    let now = unsafe { bpf_ktime_get_ns() };

    let pid_prev = data.prev_pid as u32;
    let tgid_prev = 0;
    let key_prev = TaskIdent { pid: pid_prev, tgid: tgid_prev };
    let _ = START.insert(&key_prev, &now, 0);

    let pid_next = data.next_pid as u32;
    let tgid_next = 0;
    let key_next = TaskIdent { pid: pid_next, tgid: tgid_next };

    unsafe {
        if let Some(start_ns) = START.get(&key_next) {
            let delta = now - *start_ns;
            START.remove(&key_next).ok();

            let kstack_id = KSTACK.get_stackid(&ctx, 0).unwrap_or(-1);
            let ustack_id = USTACK.get_stackid(&ctx, BPF_F_USER_STACK as u64).unwrap_or(-1);

            if let Some(mut e) = EVENTS.reserve::<OffCpuSample>(0) {
                let sample = OffCpuSample {
                    pid: pid_next,
                    tgid: tgid_next,
                    off_ns: delta,
                    kstack_id,
                    ustack_id,
                    comm: data.next_comm,
                };
                e.write(sample);
                e.submit(0);
            }
        }
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
