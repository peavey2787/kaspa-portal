mod builder;
mod fee;
mod model;
mod selection;

pub(crate) use builder::{build, build_with_binding};
pub use model::{CovenantBuildRequest, CovenantEncoding};

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
