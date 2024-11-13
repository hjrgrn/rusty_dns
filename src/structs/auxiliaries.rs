use std::error::Error;

pub type CResult<T> = std::result::Result<T, Box<dyn Error>>;
