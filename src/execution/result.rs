use unicorn::*;

use crate::result::Result;

pub struct ExecutionResult<'a> {
    pub(crate) emu: &'a mut CpuX86,
}

impl<'a> ExecutionResult<'a> {
    pub fn new(emu: &'a mut CpuX86) -> Self {
        Self { emu }
    }

    pub fn reg_read_u64(&self, reg: RegisterX86) -> Result<u64> {
        self.emu
            .reg_read(reg)
            .map_err(|_| "unable to read register".into())
    }

    pub fn reg_read_str(&self, reg: RegisterX86) -> Result<String> {
        let addr = self.reg_read_u64(reg)?;
        let mut buf = vec![0; 0x200];
        self.emu
            .mem_read(addr, &mut buf)
            .map_err(|_| "unable to read memory")?;

        Ok(
            String::from_utf8_lossy(&(buf.into_iter().take_while(|v| *v != 0).collect::<Vec<_>>()))
                .to_string(),
        )
    }

    // TODO: more helper functions
}
