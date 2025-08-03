mod symbolize;
mod collector;

use clap::Parser;
use tokio;


#[derive(clap::Parser)]
struct Opt {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// on-cpu 采样
    OnCpu {
        #[arg(short, long)]
        pid: u32,
        #[arg(short, long, default_value = "1")]
        duration: u64,
        #[arg(short, long, default_value = "99")]
        frequency: u64,
    },
    /// off-cpu 采样
    OffCpu {
        #[arg(short, long)]
        pid: u32,
        #[arg(short, long, default_value = "5")]
        duration: u64,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let opt = Opt::parse();

    match opt.cmd {
        Command::OnCpu { pid, duration, frequency } => {
            collector::on_cpu::run(pid, duration, frequency).await?;
        }
        Command::OffCpu { pid, duration } => {
            collector::off_cpu::run(pid, duration).await?;
        }
    }
    Ok(())
}