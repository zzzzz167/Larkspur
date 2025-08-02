use std::fs;
use anyhow::{Result};

pub struct KstackSymbol {
    pub offset: u64,
    pub function: Option<String>,
    pub module: Option<String>,
}

impl KstackSymbol {
    pub fn to_string_lossy(&self) -> String {
        match (self.function.as_ref(), self.module.as_ref()) {
            (Some(f), Some(module)) => format!("{} in [{}]", f, module),
            (Some(f), _) => f.clone(),
            _ => format!("0x{:x}", self.offset),
        }
    }
}

pub struct KStackResolver {
    ksyms: Vec<SymRange>,
}

impl KStackResolver {
    pub fn new() -> Result<Self> {
        let ksyms = load_ksyms()?;
        Ok(Self{
            ksyms,
        })
    }

    pub fn symbolize_stack(&self, addrs:&[u64]) -> Vec<KstackSymbol> {
        addrs.iter().map(|&a| self.symbolize_addr(a)).collect()
    }

    fn symbolize_addr(&self, addr: u64) -> KstackSymbol {
        let Some(owner) = find_owner(&*self.ksyms, addr) else {
            return fallback(addr);
        };
        KstackSymbol {
            offset: addr,
            function: Option::from(owner.name.clone()),
            module: owner.module.clone()
        }
    }
}

fn fallback(addr: u64) -> KstackSymbol {
    KstackSymbol {
        offset: addr,
        function: None,
        module: None
    }
}

struct SymRange {
    pub start: u64,
    pub end: u64,
    pub name: String,
    pub module: Option<String>, // None = kernel
}

fn load_ksyms() -> anyhow::Result<Vec<SymRange>> {
    let mut list = Vec::new();

    for line in fs::read_to_string("/proc/kallsyms")?.lines() {
        let mut parts = line.split_whitespace();
        let addr = u64::from_str_radix(parts.next().unwrap(), 16)?;
        let _type = parts.next().unwrap();
        let name = parts.next().unwrap().to_string();
        let mod_name = parts.next().map(|s| s.trim_matches(&['[', ']'][..]).to_string());

        if !list.is_empty() {
            // 把上一个符号的结束地址补成当前地址
            let last:&mut SymRange = list.last_mut().unwrap();
            last.end = addr;
        }

        list.push(SymRange {
            start: addr,
            end: 0, // 临时
            name:name.clone(),
            module: mod_name.clone(),
        });
    }

    // 最后一个符号给一个足够大的 end
    if let Some(last) = list.last_mut() {
        last.end = u64::MAX;
    }

    Ok(list)
}

fn find_owner(syms: &[SymRange], addr: u64) -> Option<&SymRange> {
    syms.binary_search_by(|r| {
        if addr < r.start {
            std::cmp::Ordering::Greater
        } else if addr >= r.end {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Equal
        }
    })
        .ok()
        .map(|idx| &syms[idx])
}
