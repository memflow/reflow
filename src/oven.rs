use crate::execution::Execution64;
use crate::params::Parameters;
use crate::stack::Stack;

use std::cell::RefCell;
use std::rc::Rc;

use memflow::prelude::v1::*;

use unicorn::*;

pub struct Reflow<'a, P: Process> {
    process: Rc<RefCell<P>>,
    stack: Option<Stack>,
    params: Option<Parameters<'a>>,
    entry_point: Address,
}

impl<'a, P: Process + 'static> Reflow<'a, P> {
    pub fn new(process: Rc<RefCell<P>>) -> Self {
        Self {
            process,
            stack: None,
            params: None,
            entry_point: Address::NULL,
        }
    }

    pub fn stack(mut self, stack: Stack) -> Self {
        self.stack = Some(stack);
        self
    }

    pub fn params(mut self, params: Parameters<'a>) -> Self {
        self.params = Some(params);
        self
    }

    pub fn entry_point(mut self, entry_point: Address) -> Self {
        self.entry_point = entry_point;
        self
    }

    pub fn run(&mut self) -> std::result::Result<(), String> {
        self.run_x64()
    }

    fn run_x64(&mut self) -> std::result::Result<(), String> {
        // step1: find module containing the address

        // step2: create unicorn context
        let mut execution = Execution64::new()?
            .build_stack(&mut self.stack.unwrap_or_default())?
            .build_params(&mut self.params.unwrap_or_default())?;
        // TODO: push ret addr

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
            let instructions = uc.mem_read_as_vec(addr, size as usize).unwrap();
            let result = cs.disasm_all(&instructions, addr).unwrap();
            print!("{}", result.to_string());
        })
        .unwrap();

        // hook to trigger final execution end
        emu.add_mem_hook(MemHookType::MEM_FETCH_PROT, 1, 0, |_, ty, addr, size, _| {
            println!("{:?}: 0x{:x} with size 0x{:x}", ty, addr, size);
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
                println!("{:?}: 0x{:x} with size 0x{:x}", ty, addr, size);
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
                println!("{:?}: 0x{:x} with size 0x{:x}", ty, addr, size);
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
                println!("{:?}: 0x{:x} with size 0x{:x}", ty, addr, size);
                map_from_process(emu, addr, &mut *cloned_proc.borrow_mut());
                true
            },
        )
        .unwrap();

        // hook for memory access debugging
        emu.add_mem_hook(MemHookType::MEM_READ, 1, 0, move |_, _, addr, size, _| {
            //println!("read at 0x{:x} with size {:x}", addr, size);
            true
        })
        .unwrap();
        emu.add_mem_hook(MemHookType::MEM_WRITE, 1, 0, |_, _, addr, size, _| {
            //println!("write at 0x{:x} with size {:x}", addr, size);
            true
        })
        .unwrap();

        // step6:
        emu.emu_start(addr.as_u64(), ret_addr.as_u64(), 0, 0)
            .expect("execution failed");

        /*
        if emu.reg_read(RegisterX86::RSP).unwrap_or_default() == ret_addr.as_u64() {
            println!("execution successful");
        } else {
            println!(
                "execution failed: {:x}",
                emu.reg_read(RegisterX86::RSP).unwrap_or_default()
            );
        }
        */

        println!("result: eax={}", emu.reg_read(RegisterX86::RAX).unwrap());

        Ok(())
    }
}

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
