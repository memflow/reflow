use crate::execution::{ExecutionResult, ExecutionX86, ExecutionX86Arch};
use crate::params::Parameters;
use crate::result::Result;
use crate::stack::Stack;

use memflow::prelude::v1::*;

pub trait Oven<'a> {
    fn set_stack(&mut self, stack: Stack) -> Result<()>;

    fn set_params(&mut self, params: Parameters<'a>) -> Result<()>;

    fn set_entry_point(&mut self, entry_point: Address) -> Result<()>;

    fn reflow<'b>(&'b mut self) -> Result<ExecutionResult<'b>>;
}

pub trait OvenBuilder<'a>: Oven<'a> {
    fn stack(&mut self, stack: Stack) -> Result<&mut Self> {
        Oven::set_stack(self, stack)?;
        Ok(self)
    }

    fn params(&mut self, params: Parameters<'a>) -> Result<&mut Self> {
        Oven::set_params(self, params)?;
        Ok(self)
    }

    fn entry_point(&mut self, entry_point: Address) -> Result<&mut Self> {
        Oven::set_entry_point(self, entry_point)?;
        Ok(self)
    }
}

impl<'a, T: Oven<'a> + ?Sized> OvenBuilder<'a> for T {}

pub fn new_oven<'a, P: 'a + Process + MemoryView>(
    process: &'a mut P,
) -> Result<Box<dyn Oven<'a> + 'a>> {
    let arch = process.info().proc_arch;
    new_oven_with_arch(process, arch)
}

pub fn new_oven_with_arch<'a, V: 'a + MemoryView>(
    mem: &'a mut V,
    arch: ArchitectureIdent,
) -> Result<Box<dyn Oven<'a> + 'a>> {
    match arch {
        ArchitectureIdent::X86(32, _) => x86_oven(ExecutionX86Arch::X8632, mem),
        ArchitectureIdent::X86(64, _) => x86_oven(ExecutionX86Arch::X8664, mem),
        ArchitectureIdent::X86(_, _) => unreachable!("invalid x86 bit width"),
        ArchitectureIdent::AArch64(_) => Err("AArch64 is not supported yet".into()),
        ArchitectureIdent::Unknown(_) => Err("Unknown process architecture".into()),
    }
}

fn x86_oven<'a, V: 'a + MemoryView>(
    arch: ExecutionX86Arch,
    mem: &'a mut V,
) -> Result<Box<dyn Oven<'a> + 'a>> {
    let execution = ExecutionX86::<V>::new(arch, mem)?;

    Ok(Box::new(execution))
}
