use clap::{Parser, Subcommand};
use std::process::Command;

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    #[command(subcommand)]
    cmd: Commands,
}


#[derive(Subcommand)]
enum Commands {
    /// 编译 eBPF 程序
    BuildEbpf {
        /// 指定 eBPF crate 名
        #[arg(short, long)]
        package: String,
    },
    /// 一键完整构建（eBPF + 用户态）
    BuildAll,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    match args.cmd {
        Commands::BuildEbpf { package} => build_ebpf(&package),
        Commands::BuildAll => {
            build_ebpf("larkspur-ebpf-on-cpu")?;
            build_user()?;
            Ok(())
        }
    }
}

fn build_ebpf(package: &str) -> anyhow::Result<()> {
    let status = Command::new("cargo")
        .current_dir(package)
        .args(&[
            "+nightly",
            "build",
            "-Z",
            "build-std=core,compiler_builtins",
            "--target",
            "bpfel-unknown-none",
        ])
    .status()?;
    if !status.success() {
        anyhow::bail!("eBPF build failed");
    }
    println!("✅ eBPF crate {} built", package);
    Ok(())
}

fn build_user() -> anyhow::Result<()> {
    let status = Command::new("cargo")
        .args(&["build", "--release"])
        .status()?;
    if !status.success() {
        anyhow::bail!("user build failed");
    }
    println!("✅ user CLI built");
    Ok(())
}