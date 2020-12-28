use std::mem::size_of;

use memflow::prelude::v1::*;

use unicorn::{CodeHookType, Cpu, CpuX86, MemHookType, Protection, RegisterX86, Unicorn};
use dataview::Pod;

/*
TODO:
The Stack object has to store an internal list of "Objects" that are passed onto the stack
once we create it with the actual unicorn engine object.

This means having an enum variant storing all pushed value refs + initial ret addr
*/

/// Represents an entry on the stack.
/// This enum is used in the `Stack` object to store the the internal state
/// of the final stack before actual 'submitting' it to unicorn-engine.
pub enum StackEntry<'a> {
    Value32(u32),
    Value64(u64),
    String(&'a str)
    // Object() // TODO: Any ?
}

pub struct Stack<'a> {
    pub base: u64,
    pub size: usize,

    // TODO: architecture agnostic

    pub entries: Vec<StackEntry<'a>>,
    pub ret_addr: u64,
}

// TODO: custom error type

impl<'a> Stack<'a> {

    // Note: maybe we dont have to do 32/64 (seperately) ~ ko1n
    pub fn push32(&mut self, value: u32) {
        self.entries.push(StackEntry::Value32(value));
    }

    pub fn push64(&mut self, value: u64) {
        self.entries.push(StackEntry::Value64(value))
    }

    // TODO: push_str()
    // TODO: push_pod()

    // TODO: final 'internal' create function that will generate the stack in unicorn engine


    pub fn create(emu: &Unicorn, base: u64, size: usize) -> Result<Self> {
        // initialize memory for stack
        emu.mem_map(
            base - size as u64,
            size,
            Protection::READ | Protection::WRITE,
        )
        .map_err(|_| Error::Bounds)?;

        // TODO: overwrite stack with 0's on re-execution

        // we leave 1 mb for local function variables here
        let stack_start_addr = base - size::mb(1) as u64;
        emu.reg_write(RegisterX86::RSP as i32, stack_start_addr)
            .map_err(|_| Error::Bounds)?;

        Ok(Self {
            base,
            size,

            entries: Vec::new(),
            ret_addr: 0,
        })
    }

    // TODO: u32 / u64
    pub fn push(&self, emu: &Unicorn, value: u64) -> Result<()> {
        let mut rsp = emu
            .reg_read(RegisterX86::RSP as i32)
            .map_err(|_| Error::Bounds)?;
        if rsp + (size_of::<u64>() as u64) > self.base {
            return Err(Error::Other("stack underflow"));
        }

        rsp -= size_of::<u64>() as u64;

        emu.mem_write(rsp, value.as_bytes())
            .map_err(|_| Error::Bounds)?;

        emu.reg_write(RegisterX86::RSP as i32, rsp)
            .map_err(|_| Error::Bounds)?;

        Ok(())
    }

    // TODO: pop

    // etc?
}
