use std::time::{Duration, Instant};
use aya::
{programs::
 {
     PerfEvent,
     PerfEventScope,
     PerfTypeId,
     SamplePolicy,
     perf_event::perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK},
 util::online_cpus,
 maps::{RingBuf, StackTraceMap},
};
use log::info;
use proc_maps::Pid;
use tokio::task;
use larkspur_common::Sample;
use crate::symbolize::{kstack, ustack};
use crate::collector::stacktrace_from_id;

pub async fn run(pid: u32, duration: u64, frequency: u64) -> anyhow::Result<()> {
    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/larkspur-on-cpu"
    )))?;

    let prog: &mut PerfEvent =
        bpf.program_mut("on_cpu_trace").unwrap().try_into()?;
    prog.load()?;

    let cpus = online_cpus().unwrap();

    for cpu in cpus {
        let scope = PerfEventScope::OneProcessOneCpu {
            pid,
            cpu
        };
        prog.attach(
            PerfTypeId::Software,
            PERF_COUNT_SW_CPU_CLOCK as u64,
            scope,
            SamplePolicy::Frequency(frequency),
            false,
        )?;
    }

    let mut ustack = StackTraceMap::try_from(bpf.take_map("USTACKS").unwrap())?;
    let mut kstack = StackTraceMap::try_from(bpf.take_map("STACKS").unwrap())?;
    let mut sample = RingBuf::try_from(bpf.take_map("SAMPLES").unwrap())?;

    let k_resolver = kstack::KStackResolver::new()?;
    let u_resolver = ustack::Resolver::new(pid as Pid)?;

    let deadline = Instant::now() + Duration::from_secs(duration);

    task::spawn_blocking(move || {
        while Instant::now() < deadline {
            if let Some(record) = sample.next() {
                let sample: &Sample = bytemuck::from_bytes(record.as_ref());

                let kaddrs = stacktrace_from_id(&mut kstack, sample.kstack_id);
                let uaddrs = stacktrace_from_id(&mut ustack, sample.ustack_id);

                let kframes = k_resolver.symbolize_stack(&kaddrs);
                let uframes = u_resolver.symbolize_stack(&uaddrs);

                info!("K frames:");
                for i in kframes {
                    info!("{:x}:{}",i.offset, i.to_string_lossy());
                }

                info!("U frames:");
                for i in uframes {
                    for a in i {
                        info!("{:x}:{}",a.offset, a.to_string_lossy());
                    }
                }
            }
        }
    }).await?;

    Ok(())
}