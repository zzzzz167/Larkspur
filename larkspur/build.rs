use anyhow::{Context as _, anyhow};
use aya_build::cargo_metadata;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_packages: Vec<_> = packages
        .into_iter()
        .filter(|p| p.name.starts_with("larkspur-ebpf"))
        .collect();

    if ebpf_packages.is_empty() {
        return Err(anyhow!("⚠️  Not found any larkspur-ebpf-*，Skipping eBPF builds {}", ebpf_packages.len()));
    }

    aya_build::build_ebpf(ebpf_packages)?;
    Ok(())
}
