mod builder;
mod fee;
mod model;
mod selection;

pub use builder::{build, build_with_binding};
pub use model::{
    CovenantBuildRequest, CovenantDustPolicy, CovenantEncoding, KIP9_MIN_CHANGE_SOMPI,
};

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
