use std::mem::size_of;

use memflow::prelude::v1::*;

use dataview::Pod;
use unicorn::{Protection, RegisterX86, Unicorn};

/// Represents an entry on the stack.
/// This enum is used in the `Stack` object to store the the internal state
/// of the final stack before actual 'submitting' it to unicorn-engine.
pub enum StackEntry<'a> {
    Value32(u32),
    Value64(u64),
    String(&'a str), // Object() // TODO: Any ?
}

pub struct Stack<'a> {
    pub base: u64,
    pub size: u64,
    pub ret_addr: u64,

    // TODO: architecture agnostic
    pub entries: Vec<StackEntry<'a>>,
}

// TODO: custom error type

impl<'a> Stack<'a> {
    /// Constructs a new Stack at the default location (low 1-32mb)
    pub fn new() -> Self {
        Self {
            base: size::mb(1) as u64,
            size: size::mb(31) as u64,

            entries: Vec::new(),
            ret_addr: 0,
        }
    }

    // TODO: check if base is page aligned
    pub fn base(mut self, base: u64) -> Self {
        self.base = base;
        self
    }

    // TODO: check if size is page aligned
    pub fn size(mut self, size: u64) -> Self {
        self.size = size;
        self
    }

    pub fn ret_addr(mut self, ret_addr: u64) -> Self {
        self.ret_addr = ret_addr;
        self
    }

    // Note: maybe we dont have to do 32/64 (seperately) ~ ko1n
    pub fn push32(mut self, value: u32) -> Self {
        self.entries.push(StackEntry::Value32(value));
        self
    }

    pub fn push64(mut self, value: u64) -> Self {
        self.entries.push(StackEntry::Value64(value));
        self
    }

    // TODO: push_str()
    // TODO: push_pod()

    pub fn build(&self, emu: &Unicorn) -> Result<()> {
        // initialize memory for stack
        emu.mem_map(
            self.base as u64,
            self.size as usize,
            Protection::READ | Protection::WRITE,
        )
        .map_err(|_| Error::Other("unable to map memory at stack base"))?;

        // TODO: overwrite stack with 0's on re-execution

        // we leave 1 mb for local function variables here
        let stack_start_addr = self.base + self.size - size::mb(1) as u64;
        emu.reg_write(RegisterX86::RSP as i32, stack_start_addr)
            .map_err(|_| Error::Other("unable to write rsp register"))?;

        // prepare stack
        for entry in self.entries.iter() {
            match entry {
                StackEntry::Value64(value) => {
                    self.build_push(emu, *value)?;
                }
                _ => {
                    println!("not implemented yet");
                }
            }
        }

        // push final ret addr
        self.build_push(emu, self.ret_addr)?;

        Ok(())
    }

    // TODO: u32
    fn build_push(&self, emu: &Unicorn, value: u64) -> Result<()> {
        let mut rsp = emu
            .reg_read(RegisterX86::RSP as i32)
            .map_err(|_| Error::Other("unable to read rsp register"))?;
        if rsp + (size_of::<u64>() as u64) > self.base + self.size {
            return Err(Error::Other("stack underflow"));
        }

        rsp -= size_of::<u64>() as u64;

        emu.mem_write(rsp, value.as_bytes())
            .map_err(|_| Error::Other("unable to write memory at rsp"))?;

        emu.reg_write(RegisterX86::RSP as i32, rsp)
            .map_err(|_| Error::Other("unable to write rsp register"))?;

        Ok(())
    }

    // TODO: pop?
}
