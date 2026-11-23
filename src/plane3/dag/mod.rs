//! Static Kahn topological sort, abstract-interpretation IFC, and async DAG executor.

pub mod executor;
pub mod ifc;
pub mod topology;

pub use executor::*;
pub use ifc::*;
pub use topology::*;
