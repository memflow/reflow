pub mod execution;
pub mod oven;
pub mod params;
pub mod result;
pub mod stack;

pub mod prelude {
    pub mod v1 {
        pub use crate::oven::{new_oven, new_oven_with_arch, Oven, OvenBuilder};
        pub use crate::params::Parameters;
        pub use crate::result::Result;
        pub use crate::stack::Stack;

        // forward exports
        pub use unicorn::RegisterX86;
    }
}
