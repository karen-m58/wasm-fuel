//! Fuel-metered execution of WebAssembly, with no dependencies.
//!
//! Two halves that fit together:
//!
//! 1. [`parser`] decodes the WebAssembly binary format - magic number, version,
//!    section order, LEB128 immediates, types, imports, exports and code - into
//!    a [`Module`]. It is strict and total: any byte string either decodes or
//!    produces a [`ParseError`] carrying the offset that broke.
//! 2. [`interp`] executes a defined subset of the instruction set on a stack
//!    machine, charging every instruction to a fuel budget from a [`CostTable`]
//!    *before* it runs. When the budget is gone the run stops with
//!    [`Trap::OutOfFuel`].
//!
//! That is enough to answer the question a sandbox actually asks: *how much
//! work did this untrusted code do, and can I stop it after N units?* It is not
//! a replacement for wasmtime - see the README for the exact subset.
//!
//! ```
//! use wasm_fuel::{CostTable, Interpreter, Trap, Val};
//!
//! // (module (func (export "square") (param i32) (result i32)
//! //   local.get 0  local.get 0  i32.mul))
//! const SQUARE: &[u8] = &[
//!     0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
//!     0x01, 0x06, 0x01, 0x60, 0x01, 0x7F, 0x01, 0x7F,
//!     0x03, 0x02, 0x01, 0x00,
//!     0x07, 0x0A, 0x01, 0x06, 0x73, 0x71, 0x75, 0x61, 0x72, 0x65, 0x00, 0x00,
//!     0x0A, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x00, 0x6C, 0x0B,
//! ];
//!
//! let module = wasm_fuel::parse(SQUARE).unwrap();
//! assert_eq!(module.describe_exports(), vec!["func square: (i32) -> i32"]);
//!
//! let mut interp = Interpreter::new(&module)
//!     .with_costs(CostTable::uniform(1))
//!     .with_fuel(1_000);
//!
//! assert_eq!(interp.call_export("square", &[Val::I32(9)]), Ok(vec![Val::I32(81)]));
//! assert_eq!(interp.fuel_consumed(), 4);
//!
//! interp.set_fuel(3);
//! assert_eq!(interp.call_export("square", &[Val::I32(9)]), Err(Trap::OutOfFuel));
//! ```

#![forbid(unsafe_code)]

pub mod fuel;
pub mod interp;
pub mod leb;
pub mod module;
pub mod parser;

pub use fuel::{CostTable, Trap};
pub use interp::{Interpreter, Val};
pub use module::{Export, ExternKind, Func, FuncType, Import, Module, ValType};
pub use parser::{parse, ParseError, ParseErrorKind};

/// Crate version, taken from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
