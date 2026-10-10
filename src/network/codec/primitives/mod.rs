#[cfg(feature = "std")]
mod reader;
#[cfg(feature = "std")]
mod writer;

#[cfg(feature = "std")]
pub(crate) use reader::WireReader;
#[cfg(feature = "std")]
pub(crate) use writer::WireWriter;
