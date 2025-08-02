use anyhow::{Context as _, anyhow};
use aya_build::cargo_metadata;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_packages: Vec<_> = packages
        .into_iter()
        .find(|p| p.name.starts_with("larkspur-ebpf-"))
        .into_iter().collect();

    if ebpf_packages.is_empty() {
        return Err(anyhow!("⚠️  没有发现任何 larkspur-ebpf-* 包，跳过 eBPF 构建"));
    }

    aya_build::build_ebpf(ebpf_packages)?;
    Ok(())
}
