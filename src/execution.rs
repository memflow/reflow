use crate::params::Parameters;
use crate::stack::Stack;

use std::mem::size_of;

use memflow::prelude::v1::*;

use unicorn::*;

pub struct Execution64 {
    emu: unicorn::CpuX86,
}

impl Execution64 {
    pub fn new() -> std::result::Result<Self, String> {
        Ok(Self {
            emu: CpuX86::new(unicorn::Mode::MODE_64)
                .map_err(|_| "failed to instantiate emulator")?,
        })
    }

    pub fn build_stack(mut self, stack: &Stack) -> std::result::Result<Self, String> {
        // initialize memory for stack
        self.emu.mem_map(
            stack.base as u64,
            stack.size as usize,
            Protection::READ | Protection::WRITE,
        )
        .map_err(|_| "unable to map memory at stack base")?;

        // initialize high memory for data stored on stack / regs
        let mut data_base = 0xFFFFFFFFFFFFFFFFu64 - size::gb(2) as u64 + 1;
        self.emu.mem_map(
            data_base,
            size::gb(1),
            Protection::READ | Protection::WRITE,
        )
        .map_err(|e| {
            println!("error: {}", e);
            "unable to map high memory for data references"
        })?;

        // TODO: allow reexecution and 0 stack

        // write stack to rsp
        let stack_start_addr = stack.base + stack.size as u64;
        self.emu.reg_write(RegisterX86::RSP, stack_start_addr)
            .map_err(|_| "unable to write rsp register")?;

        Ok(self)
    }

    pub fn build_params(mut self, params: &Parameters) -> std::result::Result<Self, String> {
        // prepare parameter
        for entry in self.entries.iter() {
            match entry {
                Param::Value64(value) => {
                    self.build_push(emu, *value)?;
                }
                Param::Str(value) => {
                    // TODO: store and shift addr
                    self.emu.mem_write(stack_data_base, value.as_bytes())
                        .map_err(|e| {
                            println!("error: {}", e);
                            "unable to write string into high mem"
                        })?;
                    //self.build_push(emu, stack_data_base)?;

                    // just a test
                    self.emu.reg_write(RegisterX86::RCX as i32, stack_data_base)
                        .map_err(|_| "unable to write rcx register")?;

                    stack_data_base += value.as_bytes().len() as u64;
                }
                _ => {
                    panic!("not implemented yet");
                }
            }
        }

        Ok(self)
    }

    pub fn build_ret_addr(mut self, ret_addr: Address) -> std::result::Result<Self, String> {
        // push final ret addr, this execution must be called after stack has been setup
        //self.build_push(self.emu, self.ret_addr)?;

        Ok(self)
    }

    fn push_to_stack(&self, value: u64) -> std::result::Result<(), &'static str> {
        let mut rsp = self.emu
            .reg_read(RegisterX86::RSP)
            .map_err(|_| "unable to read rsp register")?;
        if rsp + (size_of::<u64>() as u64) > self.base + self.size {
            return Err("stack overflow");
        }

        rsp -= size_of::<u64>() as u64;

        self.emu.mem_write(rsp, value.as_bytes())
            .map_err(|_| "unable to write memory at rsp")?;

            self.emu.reg_write(RegisterX86::RSP, rsp)
            .map_err(|_| "unable to write rsp register")?;

        Ok(())
    }
}
