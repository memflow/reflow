use log::{debug, info};

use std::cell::RefCell;
use std::sync::Arc;

use memflow::*;
use memflow_win32::*;

use memflow::error::{Error, Result};

use capstone::prelude::*;
use unicorn::{CodeHookType, Cpu, CpuX86, MemHookType, Protection, RegisterX86, Unicorn};

// TODO: prevent mapping memory thats reserved for the stack
// TODO: error handling
fn map_from_process<T: VirtualMemory>(emu: &Unicorn, addr: u64, process: &mut Win32Process<T>) {
    let page_size = emu.query(unicorn::Query::PAGE_SIZE).unwrap();
    let page_addr = Address::from(addr).as_page_aligned(page_size);
    let page = process
        .virt_mem
        .virt_read_raw(page_addr, page_size)
        .unwrap();

    // TODO: should this really be PROT_ALL ?
    emu.mem_map(page_addr.as_u64(), page_size, Protection::ALL)
        .unwrap();
    emu.mem_write(page_addr.as_u64(), &page).unwrap();
}

/*
template <typename T>
void
push(T val) {
    uint64_t stack_ptr;
    if (this->m_process->is_x64() && !this->m_process->is_wow64()) {
        stack_ptr = this->reserve_stack(sizeof(uint64_t));
    } else {
        stack_ptr = this->reserve_stack(sizeof(uint32_t));
    }
    uc_mem_write(this->m_uc, stack_ptr, &val, sizeof(T));
}


uint64_t
process_emulator::reserve_stack(uint64_t size) {
    if (this->m_process->is_x64() && !this->m_process->is_wow64()) {
        // decrease stack by 8
        uint64_t rsp = this->reg_read<uint64_t>(UC_X86_REG_RSP);
        rsp -= size;
        this->reg_write(UC_X86_REG_RSP, rsp);
        return rsp;
    } else {
        // decrease stack by 4
        uint32_t esp = this->reg_read<uint32_t>(UC_X86_REG_ESP);
        esp -= (uint32_t)size;
        this->reg_write(UC_X86_REG_ESP, esp);
        return esp;
    }
}
*/

pub struct Stack {
    pub base: u64,
    pub size: usize,
}

// TODO: custom error type

impl Stack {
    pub fn create(emu: &Unicorn, base: u64, size: usize) -> Result<Self> {
        // initialize memory for stack
        emu.reg_write(RegisterX86::RSP as i32, base)
            .map_err(|_| Error::Bounds)?;
        emu.mem_map(
            base - size as u64,
            size,
            Protection::READ | Protection::WRITE,
        )
        .map_err(|_| Error::Bounds)?;

        // set the initial ret addr to 0
        emu.mem_write(base - 8, &[0; 8])
            .map_err(|_| Error::Bounds)?;

        Ok(Self { base, size })
    }

    // push
    pub fn push(&self, emu: &Unicorn) -> Result<()> {
        // TODO: check stack underflow

        let mut rsp = emu
            .reg_read(RegisterX86::RSP as i32)
            .map_err(|_| Error::Bounds)?;
        if rsp - 8 < self.base {
            return Err(Error::Bounds);
        }

        rsp -= 8; // sizeof(u64)
        emu.reg_write(RegisterX86::RSP as i32, rsp)
            .map_err(|_| Error::Bounds)?;

        // write to rsp value
        // uc_mem_write(this->m_uc, stack_ptr, &val, sizeof(T));

        Ok(())
    }
    // pop
    // etc?
}

pub struct Oven<T: VirtualMemory> {
    process: Arc<RefCell<Win32Process<T>>>,
}

// TODO: builder pattern would be nice here
impl<'a, T: VirtualMemory + 'static> Oven<T> {
    pub fn new(process: Win32Process<T>) -> Self {
        Self {
            process: Arc::new(RefCell::new(process)),
        }
    }

    // TODO: just a TEST func
    pub fn reflow(&mut self, addr: Address) -> Result<()> {
        // TODO: dispatch per architecture - currently this assumes x64

        // step1: find module containing the address

        // step2: create unicorn context
        let mut emu = CpuX86::new(unicorn::Mode::MODE_64)
            .map_err(|_| Error::Other("failed to instantiate emulator"))?;

        // step3: read initial code-page from process
        map_from_process(emu.emu(), addr.as_u64(), &mut self.process.borrow_mut());

        // TODO: make stack size configurable (builder)
        // step4: create stack (64bit)
        let stack = Stack::create(emu.emu(), size::mb(32) as u64, size::mb(31));

        // step5: setup hooks

        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .unwrap();
        emu.add_code_hook(CodeHookType::CODE, 1, 0, move |uc, addr, size| {
            let instructions = uc.mem_read_as_vec(addr, size as usize).unwrap();
            let result = cs.disasm_all(&instructions, addr).unwrap();
            print!("{}", result.to_string());
            if addr == 0 {
                //println!("done");
                uc.emu_stop().unwrap();
            }
        })
        .unwrap();

        // hook to trigger final execution end
        emu.add_mem_hook(MemHookType::MEM_FETCH_PROT, 1, 0, |_, ty, addr, size, _| {
            debug!("{:?}: 0x{:x} with size 0x{:x}", ty, addr, size);
            if addr < size::mb(4) as u64 {
                println!("{:?}: graceful end of execution", ty);
                println!("{:?}: graceful end of execution", ty);
                println!("{:?}: graceful end of execution", ty);
                println!("{:?}: graceful end of execution", ty);
                println!("{:?}: graceful end of execution", ty);
                println!("{:?}: graceful end of execution", ty);
                println!("{:?}: graceful end of execution", ty);
            }
            false
        })
        .unwrap();

        // hook for code reloading
        let cloned_proc = self.process.clone();
        emu.add_mem_hook(
            MemHookType::MEM_FETCH_UNMAPPED,
            1,
            0,
            move |emu, ty, addr, size, val| {
                debug!("{:?}: 0x{:x} with size 0x{:x}", ty, addr, size);
                map_from_process(emu, addr, &mut cloned_proc.borrow_mut());
                true
            },
        )
        .unwrap();

        // hook for memory reading
        let cloned_proc = self.process.clone();
        emu.add_mem_hook(
            MemHookType::MEM_READ_UNMAPPED,
            1,
            0,
            move |emu, ty, addr, size, val| {
                debug!("{:?}: 0x{:x} with size 0x{:x}", ty, addr, size);
                map_from_process(emu, addr, &mut cloned_proc.borrow_mut());
                true
            },
        )
        .unwrap();

        // hook for memory writing
        let cloned_proc = self.process.clone();
        emu.add_mem_hook(
            MemHookType::MEM_WRITE_UNMAPPED,
            1,
            0,
            move |emu, ty, addr, size, val| {
                debug!("{:?}: 0x{:x} with size 0x{:x}", ty, addr, size);
                map_from_process(emu, addr, &mut cloned_proc.borrow_mut());
                true
            },
        )
        .unwrap();

        // hook for memory access debugging
        emu.add_mem_hook(MemHookType::MEM_READ, 1, 0, |_, _, addr, size, _| {
            //debug!("read at 0x{:x} with size {:x}", addr, size);
            true
        })
        .unwrap();
        emu.add_mem_hook(MemHookType::MEM_WRITE, 1, 0, |_, _, addr, size, _| {
            //debug!("write at 0x{:x} with size {:x}", addr, size);
            true
        })
        .unwrap();

        // step6:
        emu.emu_start(addr.as_u64(), (addr + size::mb(500)).as_u64(), 0, 0)
            .unwrap();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
