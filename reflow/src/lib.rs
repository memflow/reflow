use log::{debug, info};

use std::cell::RefCell;
use std::sync::Arc;

use memflow::*;
use memflow_win32::*;

use memflow::error::{Error, Result};

use unicorn::{Cpu, CpuX86, MemHookType, Protection, RegisterX86, Unicorn};

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

        // step4: create stack (64bit)
        let stack_base = size::mb(1) as u64;
        let rsp = size::mb(4) as u64;
        emu.reg_write(RegisterX86::RSP, rsp).unwrap();
        emu.mem_map(
            stack_base,
            size::mb(32),
            Protection::READ | Protection::WRITE,
        )
        .unwrap(); // 32mb stack at exactly 4gb

        // step5: setup hooks

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
