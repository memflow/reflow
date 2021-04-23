use memflow::prelude::v1::*;

#[derive(Debug, Clone)]
pub struct Stack {
    pub(crate) base: u64,
    pub(crate) size: u64,
    pub(crate) ret_addr: u64,
}

impl Stack {
    /// Constructs a new Stack at the default location (low 1-32mb)
    pub fn new() -> Self {
        Self {
            base: size::mb(1) as u64,
            size: size::mb(31) as u64,
            ret_addr: 0,
        }
    }

    // TODO: check if base is page aligned
    pub fn base(mut self, base: u64) -> Self {
        self.base = base;
        self
    }

    // TODO: check if size is page aligned
    pub fn size(mut self, size: u64) -> Self {
        self.size = size;
        self
    }

    pub fn ret_addr(mut self, ret_addr: u64) -> Self {
        self.ret_addr = ret_addr;
        self
    }
}

impl Default for Stack {
    fn default() -> Self {
        Self::new()
    }
}
