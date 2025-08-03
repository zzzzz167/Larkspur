#![no_std]

use bytemuck::{Pod, Zeroable};

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
pub struct Sample {
    pub pid:   u32,
    pub cpu:   u32,
    pub comm:  [i8; 16],
    pub kstack_id: i64,
    pub ustack_id: i64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
pub struct OffCpuSample {
    pub pid: u32,
    pub tgid: u32,
    pub off_ns: u64,
    pub kstack_id: i64,
    pub ustack_id: i64,
    pub comm: [u8; 16],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct TaskIdent {
    pub pid: u32,
    pub tgid: u32,
}