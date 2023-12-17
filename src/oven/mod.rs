mod architecture;
use architecture::OvenArchitecture;

use crate::params::{Parameter, Parameters};
use crate::stack::Stack;

use log::{debug, trace};
use std::convert::TryInto;

use memflow::prelude::v1::*;

use unicorn_engine::unicorn_const::*;
use unicorn_engine::*;

use capstone::{arch::*, *};

pub type Result<T> = std::result::Result<T, String>;

const DATA_SIZE: usize = size::mb(128);

pub struct Oven<'a, T: 'a> {
    arch: OvenArchitecture,
    pub(crate) unicorn: Unicorn<'a, ()>,
    data_base: u64,
    ret_addr: Address,
    entry_point: Address,
    mem: &'a mut T,
}

impl<'a, T: 'a + MemoryView> Oven<'a, T> {
    pub fn new(arch: ArchitectureIdent, mem: &'a mut T) -> Result<Self> {
        let arch: OvenArchitecture = arch.try_into()?;
        let unicorn = Unicorn::new(
            arch.unicorn_arch(),
            arch.unicorn_mode() | arch.unicorn_endianess(),
        )
        .map_err(|_| "failed to instantiate emulator")?;
        let data_base = arch.max_writable_addr() - DATA_SIZE as u64 + 1;
        Self {
            arch,
            unicorn,
            data_base,
            ret_addr: Address::NULL,
            entry_point: Address::NULL,
            mem,
        }
        .install_hooks()
    }

    #[allow(clippy::unnecessary_cast)]
    pub fn stack(&mut self, stack: Stack) -> Result<&mut Self> {
        self.data_base = self.arch.max_writable_addr() - DATA_SIZE as u64 + 1;

        // initialize memory for stack if needed
        if self
            .unicorn
            .mem_protect(
                stack.base as u64,
                stack.size as usize,
                Permission::READ | Permission::WRITE,
            )
            .is_err()
        {
            self.unicorn
                .mem_map(
                    stack.base as u64,
                    stack.size as usize,
                    Permission::READ | Permission::WRITE,
                )
                .map_err(|e| {
                    println!("{:?}", e);
                    "unable to map memory at stack base"
                })?;
        }

        // initialize high memory for data stored on stack / regs
        if self
            .unicorn
            .mem_protect(
                self.data_base as u64,
                DATA_SIZE,
                Permission::READ | Permission::WRITE,
            )
            .is_err()
        {
            self.unicorn
                .mem_map(
                    self.data_base,
                    DATA_SIZE,
                    Permission::READ | Permission::WRITE,
                )
                .map_err(|_| "unable to map high memory for data references")?;
        }

        // TODO: allow reexecution and 0 stack

        // write stack to rsp
        let stack_start_addr = stack.base + stack.size as u64;
        self.unicorn
            .reg_write(self.arch.reg_sp(), stack_start_addr)
            .map_err(|_| "unable to write rsp register")?;

        self.ret_addr = stack.ret_addr.into();

        Ok(self)
    }

    pub fn params(&mut self, params: Parameters<'a>) -> Result<&mut Self> {
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
                Parameter::PushBuf(size) => {
                    self.push_buf_to_stack(*size)?;
                }

                Parameter::Reg32(reg, value) => {
                    self.unicorn
                        .reg_write(*reg as i32, *value as u64)
                        .map_err(|_| "unable to write rsp register")?;
                }
                Parameter::Reg64(reg, value) => {
                    self.unicorn
                        .reg_write(*reg as i32, *value)
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
                Parameter::RegBuf(reg, size) => {
                    self.buf_to_reg(*reg, *size)?;
                }

                Parameter::MovReg(from, to) => {
                    self.mov_reg(*from, *to)?;
                }
            }
        }

        Ok(self)
    }

    pub fn entry_point(&mut self, entry_point: Address) -> Result<&mut Self> {
        self.entry_point = entry_point;
        Ok(self)
    }

    pub fn reflow(&mut self) -> Result<()> {
        self.finalize_stack()?;
        //self.map_from_mem(&mut self.mem, self.entry_point.to_umem())?;
        self.execute()
    }

    pub fn reg_read_u64(&self, reg: RegisterX86) -> Result<u64> {
        self.unicorn
            .reg_read(reg as i32)
            .map_err(|_| "unable to read register".into())
    }

    pub fn reg_read_str(&self, reg: RegisterX86) -> Result<String> {
        let addr = self.reg_read_u64(reg)?;
        let mut buf = vec![0; 0x200];
        self.unicorn
            .mem_read(addr, &mut buf)
            .map_err(|_| "unable to read memory")?;

        Ok(
            String::from_utf8_lossy(&(buf.into_iter().take_while(|v| *v != 0).collect::<Vec<_>>()))
                .to_string(),
        )
    }

    // TODO: more helper functions

    fn finalize_stack(&mut self) -> Result<()> {
        // push final ret addr, this execution must be called after stack has been setup
        self.push_to_stack(self.ret_addr.to_umem())?;
        Ok(())
    }

    fn install_hooks(mut self) -> Result<Self> {
        // disasm code hook
        if log::log_enabled!(log::Level::Debug) {
            let cs = Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()
                .map_err(|_| "unable to create capstone context".to_string())?;
            self.unicorn
                .add_code_hook(1, 0, move |uc, addr, size| {
                    let instructions = uc.mem_read_as_vec(addr, size as usize).unwrap();
                    let result = cs.disasm_all(&instructions, addr).unwrap();
                    debug!("{}", result.to_string().trim_end());
                })
                .map_err(|_| "unable to create unicorn code hook".to_string())?;
        }

        // fetch prot hook
        // TODO: implement real protection from memory
        self.unicorn
            .add_mem_hook(HookType::MEM_FETCH_PROT, 1, 0, |_, ty, addr, size, _| {
                trace!("{:?}: 0x{:x} with size 0x{:x}", ty, addr, size);
                false
            })
            .map_err(|_| "unable to create unicorn mem prot hook".to_string())?;

        // hooks for data reload
        let mem_ptr = self.mem as *mut _ as *mut ();
        self.unicorn
            .add_mem_hook(
                HookType::MEM_FETCH_UNMAPPED,
                1,
                0,
                move |emu, ty, addr, size, _| {
                    trace!("{:?}: 0x{:x} with size 0x{:x}", ty, addr, size);

                    // # Safety
                    // This is safe because the `Process` does not outlive the underlying `emu` context.
                    // Callbacks will only be executed for a given `emu` and as long as it exists.
                    let mem = unsafe { &mut *(mem_ptr as *mut T) };
                    map_from_mem(emu, mem, addr).ok();

                    true
                },
            )
            .map_err(|_| "unable to create unicorn mem fetch hook".to_string())?;

        self.unicorn
            .add_mem_hook(
                HookType::MEM_READ_UNMAPPED,
                1,
                0,
                move |emu, ty, addr, size, _| {
                    trace!("{:?}: 0x{:x} with size 0x{:x}", ty, addr, size);

                    // # Safety
                    // This is safe because the `Process` does not outlive the underlying `emu` context.
                    // Callbacks will only be executed for a given `emu` and as long as it exists.
                    let mem = unsafe { &mut *(mem_ptr as *mut T) };
                    map_from_mem(emu, mem, addr).ok();

                    true
                },
            )
            .map_err(|_| "unable to create unicorn read unmapped hook".to_string())?;

        self.unicorn
            .add_mem_hook(
                HookType::MEM_WRITE_UNMAPPED,
                1,
                0,
                move |emu, ty, addr, size, _| {
                    trace!("{:?}: 0x{:x} with size 0x{:x}", ty, addr, size);

                    // # Safety
                    // This is safe because the `Process` does not outlive the underlying `emu` context.
                    // Callbacks will only be executed for a given `emu` and as long as it exists.
                    let mem = unsafe { &mut *(mem_ptr as *mut T) };
                    map_from_mem(emu, mem, addr).ok();

                    true
                },
            )
            .map_err(|_| "unable to create unicorn write unmapped hook".to_string())?;

        // hook for memory access debugging
        self.unicorn
            .add_mem_hook(HookType::MEM_READ, 1, 0, move |_, _, addr, size, _| {
                trace!("read at 0x{:x} with size {:x}", addr, size);
                true
            })
            .map_err(|_| "unable to create unicorn mem read hook".to_string())?;

        self.unicorn
            .add_mem_hook(HookType::MEM_WRITE, 1, 0, |_, _, addr, size, _| {
                trace!("write at 0x{:x} with size {:x}", addr, size);
                true
            })
            .map_err(|_| "unable to create unicorn mem write hook".to_string())?;

        Ok(self)
    }

    fn execute(&mut self) -> Result<()> {
        self.unicorn
            .emu_start(self.entry_point.to_umem(), self.ret_addr.to_umem(), 0, 0)
            .map_err(|err| format!("unable to execute unicorn context: {:?}", err))?;
        Ok(())
    }

    fn push_to_stack(&mut self, value: u64) -> Result<()> {
        let mut sp = self
            .unicorn
            .reg_read(self.arch.reg_sp())
            .map_err(|_| "unable to read sp register")?;
        /*if rsp + (size_of::<u64>() as u64) > self.base + self.size {
            return Err("stack overflow");
        }*/

        sp -= self.arch.ptr_size() as u64;

        match self.arch.unicorn_mode() {
            unicorn_const::Mode::MODE_32 => {
                let value32 = value as u32;
                self.unicorn
                    .mem_write(sp, value32.as_bytes())
                    .map_err(|_| "unable to write memory at sp")?;
            }
            unicorn_const::Mode::MODE_64 => {
                self.unicorn
                    .mem_write(sp, value.as_bytes())
                    .map_err(|_| "unable to write memory at sp")?;
            }
            _ => unreachable!("invalid architecture"),
        }

        self.unicorn
            .reg_write(self.arch.reg_sp(), sp)
            .map_err(|_| "unable to write sp register")?;

        Ok(())
    }

    fn push_data_ref_to_stack(&mut self, data: &[u8]) -> Result<()> {
        // store in data section
        self.unicorn
            .mem_write(self.data_base, data)
            .map_err(|_| "unable to write string into high mem")?;

        // push ptr ref to stack
        self.push_to_stack(self.data_base)?;

        self.data_base += data.len() as u64;
        Ok(())
    }

    fn push_buf_to_stack(&mut self, size: usize) -> Result<()> {
        // push ptr ref to stack
        self.push_to_stack(self.data_base)?;

        self.data_base += size as u64;
        Ok(())
    }

    fn write_data_to_reg(&mut self, reg: RegisterX86, data: &[u8]) -> Result<()> {
        // store in data section
        self.unicorn
            .mem_write(self.data_base, data)
            .map_err(|_| "unable to write string into high mem")?;

        // push ptr ref to stack
        self.unicorn
            .reg_write(reg as i32, self.data_base)
            .map_err(|_| "unable to write register")?;

        self.data_base += data.len() as u64;
        Ok(())
    }

    fn buf_to_reg(&mut self, reg: RegisterX86, size: usize) -> Result<()> {
        // push ptr ref to stack
        self.unicorn
            .reg_write(reg as i32, self.data_base)
            .map_err(|_| "unable to write register")?;

        self.data_base += size as u64;
        Ok(())
    }

    fn mov_reg(&mut self, from: RegisterX86, to: RegisterX86) -> Result<()> {
        let val = self
            .unicorn
            .reg_read(from as i32)
            .map_err(|_| "unable to read register")?;

        self.unicorn
            .reg_write(to as i32, val)
            .map_err(|_| "unable to write register")?;

        Ok(())
    }

    pub fn map_from_mem(&mut self, process: &mut impl MemoryView, addr: u64) -> Result<()> {
        map_from_mem(&mut self.unicorn, process, addr)
    }
}

pub fn map_from_mem(
    emu: &mut Unicorn<'_, ()>,
    process: &mut impl MemoryView,
    addr: u64,
) -> Result<()> {
    let page_size = emu.query(unicorn_const::Query::PAGE_SIZE).unwrap();
    let page_addr = Address::from(addr).as_page_aligned(page_size);
    let page = process.read_raw(page_addr, page_size).unwrap();

    // TODO: copy perms from process
    emu.mem_map(page_addr.to_umem(), page_size, Permission::ALL)
        .map_err(|_| "unable to map memory")?;
    emu.mem_write(page_addr.to_umem(), &page)
        .map_err(|_| "unable to write memory".into())
}
