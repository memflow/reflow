use crate::execution::{Execution64, ExecutionResult};
use crate::params::Parameters;
use crate::stack::Stack;

use memflow::prelude::v1::*;

pub struct Oven<'a, P: Process> {
    process: P,
    stack: Option<Stack>,
    params: Option<Parameters<'a>>,
    entry_point: Address,
}

impl<'a, P: Process + 'static> Oven<'a, P> {
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
        self.reflow_x64()
    }

    fn reflow_x64(&mut self) -> std::result::Result<ExecutionResult, String> {
        // step1: find module containing the address

        // create unicorn context and create stack
        let stack = self.stack.as_ref().map(Clone::clone).unwrap_or_default();
        let params = self.params.as_ref().map(Clone::clone).unwrap_or_default();

        let mut execution = Execution64::<()>::new()?
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
