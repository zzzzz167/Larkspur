use anyhow::Result;
use aya::{programs::RawTracePoint, maps::{RingBuf, StackTraceMap}};
use proc_maps::Pid;
use tokio::task;
use std::time::{Duration, Instant};
use log::info;
use crate::symbolize::{kstack, ustack};
use larkspur_common::OffCpuSample;
use crate::collector::stacktrace_from_id;

pub async fn run(pid: u32, duration: u64) -> Result<()> {
    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/larkspur-off-cpu"
    )))?;

    let prog: &mut RawTracePoint =
        bpf.program_mut("off_cpu_trace").unwrap().try_into()?;
    prog.load()?;
    prog.attach("sched_switch")?;

    let mut events = RingBuf::try_from(bpf.take_map("EVENTS").unwrap())?;
    let mut kstack_map = StackTraceMap::try_from(bpf.take_map("KSTACK").unwrap())?;
    let mut ustack_map = StackTraceMap::try_from(bpf.take_map("USTACK").unwrap())?;

    let k_resolver = kstack::KStackResolver::new()?;
    let u_resolver = ustack::Resolver::new(pid as Pid)?;

    let deadline = Instant::now() + Duration::from_secs(duration);


    task::spawn_blocking(move || {
        while Instant::now() < deadline {
            if let Some(record) = events.next() {
                let sample: &OffCpuSample = bytemuck::from_bytes(record.as_ref());

                let kaddrs = stacktrace_from_id(&mut kstack_map, sample.kstack_id);
                let uaddrs = stacktrace_from_id(&mut ustack_map, sample.ustack_id);

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