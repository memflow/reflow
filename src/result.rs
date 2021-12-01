// TODO: define a proper int result

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
