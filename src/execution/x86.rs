use super::ExecutionResult;
use crate::params::{Parameter, Parameters};
use crate::stack::Stack;

use std::{marker::PhantomData, mem::size_of};

use log::{debug, trace};

use capstone::{arch::*, *};
use memflow::prelude::v1::*;
use unicorn::*;

const DATA_SIZE: usize = size::mb(128);

#[derive(Debug, Clone)]
pub enum ExecutionX86Arch {
    X8632,
    X8664,
}

impl ExecutionX86Arch {
    pub fn unicorn_mode(&self) -> unicorn::Mode {
        match self {
            ExecutionX86Arch::X8632 => unicorn::Mode::MODE_32,
            ExecutionX86Arch::X8664 => unicorn::Mode::MODE_64,
        }
    }

    pub fn max_writable_addr(&self) -> u64 {
        match self {
            ExecutionX86Arch::X8632 => u32::MAX as u64 - size::mb(1) as u64,
            ExecutionX86Arch::X8664 => u64::MAX as u64 - size::gb(1) as u64,
        }
    }

    pub fn ptr_size(&self) -> u64 {
        match self {
            ExecutionX86Arch::X8632 => size_of::<u32>() as u64,
            ExecutionX86Arch::X8664 => size_of::<u64>() as u64,
        }
    }

    pub fn reg_sp(&self) -> i32 {
        match self {
            ExecutionX86Arch::X8632 => RegisterX86::ESP as i32,
            ExecutionX86Arch::X8664 => RegisterX86::RSP as i32,
        }
    }
}

pub struct ExecutionX86<'a, T: 'a> {
    arch: ExecutionX86Arch,
    pub(crate) emu: unicorn::CpuX86,
    data_base: u64,
    _phantom: PhantomData<&'a T>,
}

impl<'a, T: 'a> ExecutionX86<'a, T> {
    pub fn new(arch: ExecutionX86Arch) -> std::result::Result<Self, String> {
        let emu = CpuX86::new(arch.unicorn_mode()).map_err(|_| "failed to instantiate emulator")?;
        let data_base = arch.max_writable_addr() - DATA_SIZE as u64 + 1;
        Ok(Self {
            arch,
            emu,
            data_base,
            _phantom: PhantomData::default(),
        })
    }

    pub fn build_stack(self, stack: &Stack) -> std::result::Result<Self, String> {
        // initialize memory for stack
        self.emu
            .mem_map(
                stack.base as u64,
                stack.size as usize,
                Protection::READ | Protection::WRITE,
            )
            .map_err(|_| "unable to map memory at stack base")?;

        // initialize high memory for data stored on stack / regs
        self.emu
            .mem_map(
                self.data_base,
                DATA_SIZE,
                Protection::READ | Protection::WRITE,
            )
            .map_err(|_| "unable to map high memory for data references")?;

        // TODO: allow reexecution and 0 stack

        // write stack to rsp
        let stack_start_addr = stack.base + stack.size as u64;
        self.emu
            .emu()
            .reg_write(self.arch.reg_sp(), stack_start_addr)
            .map_err(|_| "unable to write rsp register")?;

        Ok(self)
    }

    pub fn build_params(mut self, params: &Parameters) -> std::result::Result<Self, String> {
        for param in params.entries.iter() {
            match param {
                Parameter::Push32(value) => {
                    self.push_to_stack(*value as u64)?;
                }
                Parameter::Push64(value) => {
                    self.push_to_stack(*value)?;
                }
                Parameter::PushStr(value) => {
                    let nullstr = format!("{}\0", value);
                    self.push_data_ref_to_stack(nullstr.as_bytes())?;
                }
                Parameter::PushString(value) => {
                    let nullstr = format!("{}\0", value);
                    self.push_data_ref_to_stack(nullstr.as_bytes())?;
                }

                Parameter::Reg32(reg, value) => {
                    self.emu
                        .reg_write(*reg, *value as u64)
                        .map_err(|_| "unable to write rsp register")?;
                }
                Parameter::Reg64(reg, value) => {
                    self.emu
                        .reg_write(*reg, *value)
                        .map_err(|_| "unable to write rsp register")?;
                }
                Parameter::RegStr(reg, value) => {
                    let nullstr = format!("{}\0", value);
                    self.write_data_to_reg(*reg, nullstr.as_bytes())?;
                }
                Parameter::RegString(reg, value) => {
                    let nullstr = format!("{}\0", value);
                    self.write_data_to_reg(*reg, nullstr.as_bytes())?;
                }
            }
        }

        Ok(self)
    }

    pub fn finalize_stack(self, ret_addr: Address) -> std::result::Result<Self, String> {
        // push final ret addr, this execution must be called after stack has been setup
        self.push_to_stack(ret_addr.as_u64())?;

        // clear entire ret_addr page with 0s
        let page_size = self
            .emu
            .query(unicorn::Query::PAGE_SIZE)
            .map_err(|_| "unable to query unicorn page size")?;
        self.emu
            .mem_map(
                ret_addr.as_page_aligned(page_size).as_u64(),
                page_size,
                Protection::ALL,
            )
            .map_err(|_| "unable to map memory".to_string())?;
        self.emu
            .mem_write(
                ret_addr.as_page_aligned(page_size).as_u64(),
                vec![0u8; page_size].as_bytes(),
            )
            .map_err(|_| "unable to write memory".to_string())?;

        Ok(self)
    }

    pub fn install_hooks<P: Process + 'static>(
        mut self,
        process: &'a mut P,
    ) -> std::result::Result<Self, String> {
        // disasm code hook
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .map_err(|_| "unable to create capstone context".to_string())?;
        self.emu
            .add_code_hook(CodeHookType::CODE, 1, 0, move |uc, addr, size| {
                let instructions = uc.mem_read_as_vec(addr, size as usize).unwrap();
                let result = cs.disasm_all(&instructions, addr).unwrap();
                debug!("{}", result.to_string().trim_end());
            })
            .map_err(|_| "unable to create unicorn code hook".to_string())?;

        // fetch prot hook
        // TODO: implement real protection from memory
        self.emu
            .add_mem_hook(MemHookType::MEM_FETCH_PROT, 1, 0, |_, ty, addr, size, _| {
                trace!("{:?}: 0x{:x} with size 0x{:x}", ty, addr, size);
                false
            })
            .map_err(|_| "unable to create unicorn mem prot hook".to_string())?;

        // hooks for data reload
        let process_ptr = process as *mut _;
        self.emu
            .add_mem_hook(
                MemHookType::MEM_FETCH_UNMAPPED,
                1,
                0,
                move |emu, ty, addr, size, _| {
                    trace!("{:?}: 0x{:x} with size 0x{:x}", ty, addr, size);

                    // # Safety
                    // This is safe because the `Process` does not outlive the underlying `emu` context.
                    // Callbacks will only be executed for a given `emu` and as long as it exists.
                    let proc = unsafe { &mut *process_ptr };
                    map_from_process(emu, proc, addr).ok();

                    true
                },
            )
            .map_err(|_| "unable to create unicorn mem fetch hook".to_string())?;

        self.emu
            .add_mem_hook(
                MemHookType::MEM_READ_UNMAPPED,
                1,
                0,
                move |emu, ty, addr, size, _| {
                    trace!("{:?}: 0x{:x} with size 0x{:x}", ty, addr, size);

                    // # Safety
                    // This is safe because the `Process` does not outlive the underlying `emu` context.
                    // Callbacks will only be executed for a given `emu` and as long as it exists.
                    let proc = unsafe { &mut *process_ptr };
                    map_from_process(emu, proc, addr).ok();

                    true
                },
            )
            .map_err(|_| "unable to create unicorn read unmapped hook".to_string())?;

        let process_ptr = process as *mut _;
        self.emu
            .add_mem_hook(
                MemHookType::MEM_WRITE_UNMAPPED,
                1,
                0,
                move |emu, ty, addr, size, _| {
                    trace!("{:?}: 0x{:x} with size 0x{:x}", ty, addr, size);

                    // # Safety
                    // This is safe because the `Process` does not outlive the underlying `emu` context.
                    // Callbacks will only be executed for a given `emu` and as long as it exists.
                    let proc = unsafe { &mut *process_ptr };
                    map_from_process(emu, proc, addr).ok();

                    true
                },
            )
            .map_err(|_| "unable to create unicorn write unmapped hook".to_string())?;

        // hook for memory access debugging
        self.emu
            .add_mem_hook(MemHookType::MEM_READ, 1, 0, move |_, _, addr, size, _| {
                trace!("read at 0x{:x} with size {:x}", addr, size);
                true
            })
            .map_err(|_| "unable to create unicorn mem read hook".to_string())?;

        self.emu
            .add_mem_hook(MemHookType::MEM_WRITE, 1, 0, |_, _, addr, size, _| {
                trace!("write at 0x{:x} with size {:x}", addr, size);
                true
            })
            .map_err(|_| "unable to create unicorn mem write hook".to_string())?;

        Ok(self)
    }

    pub fn execute(
        self,
        entry_point: Address,
        ret_addr: Address,
    ) -> std::result::Result<ExecutionResult, String> {
        self.emu
            .emu_start(entry_point.as_u64(), ret_addr.as_u64(), 0, 0)
            .map_err(|err| format!("unable to execute unicorn context: {}", err))?;
        Ok(ExecutionResult::new(self.emu))
    }

    fn push_to_stack(&self, value: u64) -> std::result::Result<(), &'static str> {
        let mut sp = self
            .emu
            .emu()
            .reg_read(self.arch.reg_sp())
            .map_err(|_| "unable to read sp register")?;
        /*if rsp + (size_of::<u64>() as u64) > self.base + self.size {
            return Err("stack overflow");
        }*/

        sp -= self.arch.ptr_size();

        match self.arch {
            ExecutionX86Arch::X8632 => {
                let value32 = value as u32;
                self.emu
                    .mem_write(sp, value32.as_bytes())
                    .map_err(|_| "unable to write memory at sp")?;
            }
            ExecutionX86Arch::X8664 => {
                self.emu
                    .mem_write(sp, value.as_bytes())
                    .map_err(|_| "unable to write memory at sp")?;
            }
        }

        self.emu
            .emu()
            .reg_write(self.arch.reg_sp(), sp)
            .map_err(|_| "unable to write sp register")?;

        Ok(())
    }

    fn push_data_ref_to_stack(&mut self, data: &[u8]) -> std::result::Result<(), String> {
        // store in data section
        self.emu
            .mem_write(self.data_base, data)
            .map_err(|_| "unable to write string into high mem")?;

        // push ptr ref to stack
        self.push_to_stack(self.data_base)?;

        self.data_base += data.len() as u64;
        Ok(())
    }

    fn write_data_to_reg(
        &mut self,
        reg: RegisterX86,
        data: &[u8],
    ) -> std::result::Result<(), String> {
        // store in data section
        self.emu
            .mem_write(self.data_base, data)
            .map_err(|_| "unable to write string into high mem")?;

        // push ptr ref to stack
        self.emu
            .reg_write(reg, self.data_base)
            .map_err(|_| "unable to write register")?;

        self.data_base += data.len() as u64;
        Ok(())
    }

    pub fn map_from_process<P: Process>(
        &mut self,
        process: &mut P,
        addr: u64,
    ) -> std::result::Result<(), String> {
        map_from_process(self.emu.emu(), process, addr)
    }
}

pub fn map_from_process<P: Process>(
    emu: &unicorn::Unicorn,
    process: &mut P,
    addr: u64,
) -> std::result::Result<(), String> {
    let page_size = emu.query(unicorn::Query::PAGE_SIZE).unwrap();
    let page_addr = Address::from(addr).as_page_aligned(page_size);
    let page = process
        .virt_mem()
        .virt_read_raw(page_addr, page_size)
        .unwrap();

    // TODO: copy perms from process
    emu.mem_map(page_addr.as_u64(), page_size, Protection::ALL)
        .map_err(|_| "unable to map memory".to_string())?;
    emu.mem_write(page_addr.as_u64(), &page)
        .map_err(|_| "unable to write memory".to_string())
}
