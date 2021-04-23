use unicorn::*;

pub struct ExecutionResult {
    pub(crate) emu: CpuX86,
}

impl ExecutionResult {
    pub fn new(emu: CpuX86) -> Self {
        Self { emu }
    }

    pub fn reg_read_u64(&self, reg: RegisterX86) -> std::result::Result<u64, &'static str> {
        self.emu
            .reg_read(reg)
            .map_err(|_| "unable to read register")
    }

    // TODO: more helper functions
}
