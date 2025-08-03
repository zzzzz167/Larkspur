use proc_maps::MapRange;
use std::fs;
use std::path::Path;

use anyhow::Result;
use goblin::elf::{Elf, note::NT_GNU_BUILD_ID};
use log::{debug};
use proc_maps::{get_process_maps, Pid};
use blazesym::{symbolize, symbolize::Symbolizer};

thread_local! {
    static SYMBOLIZER: Symbolizer = Symbolizer::new();
}

pub struct UstackSymbol {
    pub function: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub offset: u64,
    pub inline: bool
}

impl UstackSymbol {
    pub fn to_string_lossy(&self) -> String {
        match (self.function.as_ref(), self.file.as_ref(), self.line) {
            (Some(f), Some(file), Some(line)) => format!("{} at {}:{}", f, file, line),
            (Some(f), _, _) => f.clone(),
            _ => format!("0x{:x}", self.offset),
        }
    }
}

pub struct Resolver{
    pid: Pid,
    maps: Vec<MapRange>,
}

impl Resolver {
    pub fn new(pid: Pid) -> anyhow::Result<Self> {
        let maps = get_process_maps(pid)?;
        Ok(Self { pid, maps })
    }

    fn runtime_addr_to_offset(&self, addr:u64) -> Option<(String, u64)> {
        let map = self.maps.iter().find(|m| {
            addr >= m.start() as u64 && addr < (m.start() + m.size()) as u64
        })?;

        let offset = addr - map.start() as u64 + map.offset as u64;

        let path = map
            .filename()
            .and_then(|p| p.to_str())
            .unwrap_or("-")
            .to_string();

        debug!("{}", path);
        Some((path, offset))
    }

    pub fn symbolize_addr(&self, addr: u64) -> Vec<UstackSymbol> {
        let Some((elf_path, offset)) = self.runtime_addr_to_offset(addr) else {
            return vec![UstackSymbol {
                offset: addr,
                function: None,
                file: None,
                line: None,
                inline: false
            }];
        };

        symbolize_elf(&elf_path, offset).unwrap_or_else(|_| vec![UstackSymbol {
            offset,
            function: None,
            file: None,
            line: None,
            inline: false
        }])
    }

    pub fn symbolize_stack(&self, addrs: &[u64]) -> Vec<Vec<UstackSymbol>> {
        addrs
            .iter()
            .map(|&addr| self.symbolize_addr(addr))
            .collect()
    }
}


pub(crate) fn read_build_id(path: &Path) -> Result<Option<String>> {
    let buf = fs::read(path)?;
    let elf = Elf::parse(&buf)?;

    if let Some(iter) = elf.iter_note_sections(&buf, Some(".note.gnu.build-id")) {
        for note in iter {
            let note = note?;
            if note.name == "GNU" && note.n_type == NT_GNU_BUILD_ID {
                return Ok(Some(hex::encode(&note.desc)));
            }
        }
    }

    if let Some(iter) = elf.iter_note_headers(&buf) {
        for note in iter {
            let note = note?;
            if note.name == "GNU" && note.n_type == NT_GNU_BUILD_ID {
                return Ok(Some(hex::encode(&note.desc)));
            }
        }
    }

    Ok(None)
}

fn find_debug_path(original: &str) -> Option<String> {
    if let Ok(Some(build_id)) = read_build_id(Path::new(original)) {
        let (dir, file) = build_id.split_at(2);
        let p = format!("/usr/lib/debug/.build-id/{}/{}.debug", dir, &file);
        if Path::new(&p).is_file() {
            debug!("found debug via build-id: {}", p);
            return Some(p);
        }
    }

    if original.starts_with('/') {
        let p = format!("/usr/lib/debug{}", original);
        if Path::new(&p).is_file() {
            debug!("found debug via path: {}", p);
            return Some(p);
        }
    }

    None
}

fn symbolize_elf(binary_path: &str, offset: u64) ->Result<Vec<UstackSymbol>> {
    let res = symbolize_with_path(binary_path, offset)?;
    if !res.is_empty() {
        return Ok(res);
    }

    if let Some(debug_path) = find_debug_path(binary_path) {
        let res = symbolize_with_path(&debug_path, offset)?;
        if !res.is_empty() {
            return Ok(res);
        }
    }



    Ok(vec![UstackSymbol {
            offset,
            function: None,
            file: None,
            line: None,
            inline: false
    }])
}


fn symbolize_with_path(path: &str, offset: u64) -> Result<Vec<UstackSymbol>> {
    SYMBOLIZER.with(|symbolizer| {
        let src = symbolize::source::Source::Elf(symbolize::source::Elf::new(path));
        let syms = symbolizer
            .symbolize(&src, symbolize::Input::VirtOffset(&[offset]))
            .map_err(|e| anyhow::anyhow!("blazesym error: {e}"))?;
        let mut out = Vec::with_capacity(syms.len());


        for sym in syms {
            match sym {
                symbolize::Symbolized::Sym(s) => {out.push(UstackSymbol {
                    offset,
                    function: Some(s.name.into_owned()),
                    file: s
                        .code_info
                        .as_ref()
                        .map(|ci| {
                            ci.dir
                                .as_ref()
                                .map(|d| d.join(&ci.file))
                                .unwrap_or_else(|| Path::new(&ci.file).to_path_buf())
                        })
                        .map(|p| p.to_string_lossy().into_owned()),
                    line: s.code_info.as_ref().and_then(|ci| ci.line),
                    inline: false
                });
                for inl in &*s.inlined{
                    out.push(UstackSymbol{
                        offset,
                        function: Some(inl.name.to_string()),
                        file: s
                            .code_info
                            .as_ref()
                            .map(|ci| {
                                ci.dir
                                    .as_ref()
                                    .map(|d| d.join(&ci.file))
                                    .unwrap_or_else(|| Path::new(&ci.file).to_path_buf())
                            })
                            .map(|p| p.to_string_lossy().into_owned()),
                        line: inl.code_info.as_ref().and_then(|ci| ci.line),
                        inline: true
                    })
                }},
                symbolize::Symbolized::Unknown(_) => {}
            }
        }

        Ok(out)
    })
}

