use aya::maps::StackTraceMap;

pub mod on_cpu;
pub mod off_cpu;

pub fn stacktrace_from_id(map: &mut StackTraceMap<aya::maps::MapData>, id: i64) -> Vec<u64> {
    if id < 0 {
        return Vec::new();
    }
    map.get(&(id as u32), 0)
        .map(|t| t.frames().iter().map(|f| f.ip).collect())
        .unwrap_or_default()
}