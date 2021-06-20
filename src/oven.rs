use crate::execution::{ExecutionResult, ExecutionX86, ExecutionX86Arch};
use crate::params::Parameters;
use crate::stack::Stack;

use memflow::prelude::v1::*;

pub struct Oven<'a, P: Process + AsVirtualMemory> {
    process: P,
    stack: Option<Stack>,
    params: Option<Parameters<'a>>,
    entry_point: Address,
}

impl<'a, P: 'static + Process + AsVirtualMemory> Oven<'a, P> {
    pub fn new(process: P) -> Self {
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

    pub fn reflow(&mut self) -> std::result::Result<ExecutionResult, String> {
        match self.process.info().proc_arch {
            ArchitectureIdent::X86(32, _) => self.reflow_x86(ExecutionX86Arch::X8632),
            ArchitectureIdent::X86(64, _) => self.reflow_x86(ExecutionX86Arch::X8664),
            ArchitectureIdent::X86(_, _) => unreachable!("invalid x86 bit width"),
            ArchitectureIdent::AArch64(_) => Err("AArch64 is not supported yet".into()),
            ArchitectureIdent::Unknown => Err("Unknown process architecture".into()),
        }
    }

    fn reflow_x86(
        &mut self,
        arch: ExecutionX86Arch,
    ) -> std::result::Result<ExecutionResult, String> {
        // step1: find module containing the address

        // create unicorn context and create stack
        let stack = self.stack.as_ref().map(Clone::clone).unwrap_or_default();
        let params = self.params.as_ref().map(Clone::clone).unwrap_or_default();

        let mut execution = ExecutionX86::<()>::new(arch)?
            .build_stack(&stack)?
            .build_params(&params)?
            .finalize_stack(stack.ret_addr.into())?;

        // read initial code page from process
        execution.map_from_process(&mut self.process, self.entry_point.as_u64())?;

        // install hooks
        execution = execution.install_hooks(&mut self.process)?;

        // run emulator
        execution.execute(self.entry_point, stack.ret_addr.into())
    }
}
