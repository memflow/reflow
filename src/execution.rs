pub mod result;
pub use result::ExecutionResult;

use crate::params::{Parameter, Parameters};
use crate::stack::Stack;

use std::{marker::PhantomData, mem::size_of};

use log::{debug, trace};

use capstone::{arch::*, *};
use memflow::prelude::v1::*;
use unicorn::*;

pub struct Execution64<'a, T: 'a> {
    pub(crate) emu: unicorn::CpuX86,
    data_base: u64,
    _phantom: PhantomData<&'a T>,
}

impl<'a, T: 'a> Execution64<'a, T> {
    pub fn new() -> std::result::Result<Self, String> {
        Ok(Self {
            emu: CpuX86::new(unicorn::Mode::MODE_64)
                .map_err(|_| "failed to instantiate emulator")?,
            data_base: u64::MAX - size::gb(2) as u64 + 1,
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
        self.emu
            .reg_write(RegisterX86::RSP, stack_start_addr)
            .map_err(|_| "unable to write rsp register")?;

        Ok(self)
    }

    pub fn build_params(mut self, params: &Parameters) -> std::result::Result<Self, String> {
        for param in params.entries.iter() {
            match param {
                Parameter::Push64(value) => {
                    self.push_to_stack(*value)?;
                }
                Parameter::PushStr(value) => {
                    let nullstr = format!("{}\0", value);
                    self.push_data_to_stack(nullstr.as_bytes())?;
                }
                Parameter::PushString(value) => {
                    let nullstr = format!("{}\0", value);
                    self.push_data_to_stack(nullstr.as_bytes())?;
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
                _ => {
                    panic!("not implemented yet");
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
                println!("{:?}: 0x{:x} with size 0x{:x}", ty, addr, size);
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
        let mut rsp = self
            .emu
            .reg_read(RegisterX86::RSP)
            .map_err(|_| "unable to read rsp register")?;
        /*if rsp + (size_of::<u64>() as u64) > self.base + self.size {
            return Err("stack overflow");
        }*/

        rsp -= size_of::<u64>() as u64;

        self.emu
            .mem_write(rsp, value.as_bytes())
            .map_err(|_| "unable to write memory at rsp")?;

        self.emu
            .reg_write(RegisterX86::RSP, rsp)
            .map_err(|_| "unable to write rsp register")?;

        Ok(())
    }

    fn push_data_to_stack(&mut self, data: &[u8]) -> std::result::Result<(), String> {
        // store in data section
        self.emu.mem_write(self.data_base, data).map_err(|e| {
            println!("error: {}", e);
            "unable to write string into high mem"
        })?;

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
        self.emu.mem_write(self.data_base, data).map_err(|e| {
            println!("error: {}", e);
            "unable to write string into high mem"
        })?;

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
