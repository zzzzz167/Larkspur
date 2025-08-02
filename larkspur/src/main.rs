mod ustack;
mod kstack;


use aya::{
    programs::{PerfEvent,
               perf_event::{PerfEventScope,perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK},
               PerfTypeId,
               SamplePolicy
    },
    util::online_cpus,
    maps::{RingBuf, StackTraceMap},
};
use clap::Parser;
use std::{time::Duration, io::{BufWriter, Cursor}, fs::File};
use std::io::Write;
use aya::maps::MapData;
use log::{debug, info};
use larkspur_common::Sample;
use crossbeam_channel::{bounded, RecvTimeoutError};

use inferno::flamegraph::{from_reader, Options};

use tokio::runtime;
use crate::ustack::Resover;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: i32,

    #[clap(short, long, default_value = "1")]
    duration: u64,

    #[clap(short, long, default_value = "9")]
    frequency: u64,
}

fn main() -> Result<(), anyhow::Error>  {
    let opt = Opt::parse();

    env_logger::init();

    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/larkspur-on-cpu"
    )))?;

    let program: &mut PerfEvent =
        bpf.program_mut("larkspur-on-cpu").unwrap().try_into()?;
    program.load()?;

    let cpus = online_cpus().unwrap();

    for cpu in cpus {
        let scope = PerfEventScope::OneProcessOneCpu {
            pid: opt.pid as u32,
            cpu
        };
        program.attach(
            PerfTypeId::Software,
            PERF_COUNT_SW_CPU_CLOCK as u64,
            scope,
            SamplePolicy::Frequency(opt.frequency),
            false,
        )?;
    }

    let u_stacks_map = bpf.take_map("USTACKS").unwrap();
    let k_stacks_map = bpf.take_map("STACKS").unwrap();
    let samples_map = bpf.take_map("SAMPLES").unwrap();

    let mut u_stacks = StackTraceMap::try_from(u_stacks_map)?;
    let mut k_stacks = StackTraceMap::try_from(k_stacks_map)?;
    let mut samples = RingBuf::try_from(samples_map)?;


    let reor = Resover::new(opt.pid)?;
    let k_resolver = kstack::KStackResolver::new().expect("kstack resolver");

    let (tx, rx) = bounded::<(Sample, Vec<u64>, Vec<u64>)>(1024);

    let parse_handle = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(opt.duration);
        loop {
            if std::time::Instant::now() > deadline {
                break;
            }
            if let Some(record) = samples.next() {
                let sample: &Sample = bytemuck::from_bytes(record.as_ref());
                debug!("sample:{:?}", sample);
                let u_addrs = stacktrace_from_id(&mut u_stacks, sample.ustack_id);
                let k_addrs = stacktrace_from_id(&mut k_stacks, sample.kstack_id);
                if tx.send((sample.clone(), k_addrs, u_addrs)).is_err() {
                    break; // 主线程已退出
                }
            }
        }
    });

    info!("实时分析开始，采样 {} 秒后自动结束...", opt.duration);
    let rt = runtime::Runtime::new()?;


    let mut folded = String::new();
    rt.block_on(async {
        tokio::task::spawn_blocking(move || {

            loop {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok((_sample, k_addrs, u_addrs)) => {

                        let mut k_frames = k_resolver.symbolize_stack(&k_addrs);
                        let mut u_frames = reor.symbolize_stack(&u_addrs);


                        let mut folded_line = String::new();

                        u_frames.reverse();

                        for mut frames in u_frames {
                            frames.reverse();
                            for f in frames {
                                if let Some(func) = f.function {
                                    folded_line.push_str(&func);
                                    folded_line.push(';');
                                }
                            }
                        }

                        if !folded_line.is_empty() {
                            folded_line.pop(); // 去掉最后的 ';'
                            folded.push_str(&folded_line);
                            folded.push(' ');
                            folded.push_str(&1.to_string());
                            folded.push('\n');
                        }

                        let mut k_line = String::new();

                        k_frames.reverse();

                        for f in k_frames {
                            k_line.push_str(&f.function.unwrap_or_else(|| "unknown".into()));
                            k_line.push(';');
                        }
                        if !k_line.is_empty() {
                            k_line.pop();
                            folded.push_str(&k_line);
                            folded.push(' ');
                            folded.push_str(&1.to_string());
                            folded.push('\n');
                        }

                    },
                    Err(RecvTimeoutError::Disconnected) => break,
                    Err(RecvTimeoutError::Timeout) => continue,
                }
            }
            let mut opts = Options::default();
            opts.title = format!("EmberSight PID {}", opt.pid);
            let mut out = BufWriter::new(Vec::new());
            from_reader(&mut opts, &mut Cursor::new(folded), &mut out).unwrap();
            let svg = out.into_inner().unwrap();
            File::create("flamegraph.svg").unwrap().write_all(&svg).expect("TODO: panic message");
            
        })
            .await?;
        Ok::<(), anyhow::Error>(())
    })?;

    parse_handle.join().unwrap();
    info!("采样结束");

    Ok(())
}

fn stacktrace_from_id(map: &mut StackTraceMap<MapData>, id: i64) -> Vec<u64> {
    if id < 0 { return Vec::new(); }
    let trace = map.get(&(id as u32), 0).unwrap();
    trace.frames().into_iter().map(|f| f.ip).collect()
}
