use std::mem::size_of;

use memflow::prelude::v1::*;

use dataview::Pod;
use unicorn::{Protection, RegisterX86, Unicorn};

pub enum PointerWidth {
    Pointer32,
    Pointer64,
}

/// Represents an entry on the stack.
/// This enum is used in the `Stack` object to store the the internal state
/// of the final stack before actual 'submitting' it to unicorn-engine.
pub enum StackEntry<'a> {
    Value32(u32),
    Value64(u64),
    Str(&'a str), // Object() // TODO: Any ?
}

// TODO: 32/64bit stacks
pub struct Stack<'a> {
    pub ptr_width: PointerWidth,

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
            ptr_width: PointerWidth::Pointer64,

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

    pub fn push_str(mut self, value: &'a str) -> Self {
        self.entries.push(StackEntry::Str(value));
        self
    }

    // TODO: push_str()
    // TODO: push_pod()

    pub fn build(&self, emu: &Unicorn) -> std::result::Result<(), &'static str> {
        // initialize memory for stack
        emu.mem_map(
            self.base as u64,
            self.size as usize,
            Protection::READ | Protection::WRITE,
        )
        .map_err(|_| "unable to map memory at stack base")?;

        // initialize high memory for stack pointers
        let mut stack_data_base = 0xFFFFFFFFFFFFFFFFu64 - size::gb(2) as u64 + 1;
        emu.mem_map(
            stack_data_base,
            size::gb(1),
            Protection::READ | Protection::WRITE,
        )
        .map_err(|e| {
            println!("error: {}", e);
            "unable to map high memory"
        })?;

        // TODO: overwrite stack with 0's on re-execution

        // we leave 1 mb for local function variables here
        let stack_start_addr = self.base + self.size - size::mb(1) as u64;
        emu.reg_write(RegisterX86::RSP as i32, stack_start_addr)
            .map_err(|_| "unable to write rsp register")?;

        // prepare stack
        for entry in self.entries.iter() {
            match entry {
                StackEntry::Value64(value) => {
                    self.build_push(emu, *value)?;
                }
                StackEntry::Str(value) => {
                    // TODO: store and shift addr
                    emu.mem_write(stack_data_base, value.as_bytes())
                        .map_err(|e| {
                            println!("error: {}", e);
                            "unable to write string into high mem"
                        })?;
                    //self.build_push(emu, stack_data_base)?;

                    // just a test
                    emu.reg_write(RegisterX86::RCX as i32, stack_data_base)
                        .map_err(|_| "unable to write rcx register")?;

                    stack_data_base += value.as_bytes().len() as u64;
                }
                _ => {
                    panic!("not implemented yet");
                }
            }
        }

        // push final ret addr
        self.build_push(emu, self.ret_addr)?;

        Ok(())
    }

    // TODO: u32
    fn build_push(&self, emu: &Unicorn, value: u64) -> std::result::Result<(), &'static str> {
        let mut rsp = emu
            .reg_read(RegisterX86::RSP as i32)
            .map_err(|_| "unable to read rsp register")?;
        if rsp + (size_of::<u64>() as u64) > self.base + self.size {
            return Err("stack underflow");
        }

        rsp -= size_of::<u64>() as u64;

        emu.mem_write(rsp, value.as_bytes())
            .map_err(|_| "unable to write memory at rsp")?;

        emu.reg_write(RegisterX86::RSP as i32, rsp)
            .map_err(|_| "unable to write rsp register")?;

        Ok(())
    }

    // TODO: pop?
}
