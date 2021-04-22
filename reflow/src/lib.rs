pub mod stack;
pub use stack::Stack;

use log::{debug, info};

use std::cell::RefCell;
use std::mem::size_of;
use std::rc::Rc;
use std::sync::Arc;

use memflow::prelude::v1::*;

use memflow::error::{Error, Result};

use capstone::prelude::*;
use dataview::Pod;
use unicorn::{CodeHookType, Cpu, CpuX86, MemHookType, Protection, RegisterX86, Unicorn};

// TODO: prevent mapping memory thats reserved for the stack
// TODO: error handling
fn map_from_process<P: Process>(emu: &Unicorn, addr: u64, process: &mut P) {
    let page_size = emu.query(unicorn::Query::PAGE_SIZE).unwrap();
    let page_addr = Address::from(addr).as_page_aligned(page_size);
    let page = process
        .virt_mem()
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

pub struct Oven<'a, P: Process> {
    process: Rc<RefCell<P>>,
    stack: Stack<'a>,
}

// TODO: builder pattern would be nice here
impl<'a, P: Process + 'static> Oven<'a, P> {
    pub fn new(process: Rc<RefCell<P>>, stack: Stack<'a>) -> Self {
        Self { process, stack }
    }

    // TODO: just a TEST func
    pub fn reflow(&mut self, addr: Address) -> std::result::Result<(), &'static str> {
        // TODO: dispatch per architecture - currently this assumes x64

        // step1: find module containing the address

        // step2: create unicorn context
        let mut emu =
            CpuX86::new(unicorn::Mode::MODE_64).map_err(|_| "failed to instantiate emulator")?;

        // step4: create stack (64bit)
        self.stack
            .build(emu.emu())
            .map_err(|_| "unable to build stack")?;

        // step3: read initial code-page from process
        map_from_process(emu.emu(), addr.as_u64(), &mut *self.process.borrow_mut());

        // step4.2: clear entire ret_addr page with 0's
        let ret_addr = Address::from(self.stack.ret_addr);
        let ret_data = [0u8; size::kb(4)];
        emu.mem_map(
            ret_addr.as_page_aligned(size::kb(4)).as_u64(),
            size::kb(4),
            Protection::ALL,
        )
        .unwrap();
        emu.mem_write(ret_addr.as_page_aligned(size::kb(4)).as_u64(), &ret_data)
            .unwrap();

        // test: push str

        // step5: setup hooks

        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .unwrap();
        emu.add_code_hook(CodeHookType::CODE, 1, 0, move |uc, addr, size| {
            if addr != ret_addr.as_u64() {
                let instructions = uc.mem_read_as_vec(addr, size as usize).unwrap();
                let result = cs.disasm_all(&instructions, addr).unwrap();
                print!("{}", result.to_string());
            } else {
                println!("reached final ret!");
                println!(
                    "result: eax={}",
                    uc.reg_read(RegisterX86::RAX as i32).unwrap()
                );
                uc.emu_stop().unwrap();
            }
        })
        .unwrap();

        // hook to trigger final execution end
        emu.add_mem_hook(MemHookType::MEM_FETCH_PROT, 1, 0, |_, ty, addr, size, _| {
            debug!("{:?}: 0x{:x} with size 0x{:x}", ty, addr, size);
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
                // TODO: check final ret addr before mapping
                debug!("{:?}: 0x{:x} with size 0x{:x}", ty, addr, size);
                if addr == ret_addr.as_u64() {
                    println!("reached end of execution");
                //emu.emu_stop().unwrap();
                // TODO: put 00 00 in execution context at ret_addr
                } else {
                }
                map_from_process(emu, addr, &mut *cloned_proc.borrow_mut());
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
                map_from_process(emu, addr, &mut *cloned_proc.borrow_mut());
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
                map_from_process(emu, addr, &mut *cloned_proc.borrow_mut());
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
            .ok();

        if emu.reg_read(RegisterX86::RSP).unwrap_or_default() == ret_addr.as_u64() {
            println!("execution successful");
        } else {
            println!(
                "execution failed: {:x}",
                emu.reg_read(RegisterX86::RSP).unwrap_or_default()
            );
        }

        Ok(())
    }
}
