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