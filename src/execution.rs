pub mod result;
pub use result::ExecutionResult;

pub mod x86;
pub use x86::{ExecutionX86, ExecutionX86Arch};

use crate::params::Parameters;
use crate::stack::Stack;

use memflow::prelude::v1::*;

pub type Result<T> = std::result::Result<T, String>;

pub trait Execution<'a> {
    fn set_stack(&mut self, stack: Stack) -> Result<()>;

    fn set_params(&mut self, params: Parameters<'a>) -> Result<()>;

    fn set_entry_point(&mut self, entry_point: Address) -> Result<()>;

    fn reflow<'b>(&'b mut self) -> Result<ExecutionResult<'b>>;
}

pub trait ExecutionHelper<'a>: Execution<'a> {
    fn stack(&mut self, stack: Stack) -> Result<&mut Self> {
        Execution::set_stack(self, stack)?;
        Ok(self)
    }

    fn params(&mut self, params: Parameters<'a>) -> Result<&mut Self> {
        Execution::set_params(self, params)?;
        Ok(self)
    }

    fn entry_point(&mut self, entry_point: Address) -> Result<&mut Self> {
        Execution::set_entry_point(self, entry_point)?;
        Ok(self)
    }
}

impl<'a, T: Execution<'a> + ?Sized> ExecutionHelper<'a> for T {}
