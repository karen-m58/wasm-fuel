//! The pieces of a WebAssembly module this crate understands.
//!
//! A parsed [`Module`] keeps the type, import, function, export, start and code
//! sections. Sections that only matter to features this crate does not
//! implement (memory, tables, globals, element and data segments) are recorded
//! as present and then skipped, so that a module using them still parses and
//! still lists its exports - it simply cannot be executed if the code touches
//! them.

use std::fmt;

/// A WebAssembly value type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValType {
    /// 32-bit integer.
    I32,
    /// 64-bit integer.
    I64,
    /// 32-bit float. Parsed and reported, never executed.
    F32,
    /// 64-bit float. Parsed and reported, never executed.
    F64,
}

impl ValType {
    /// Decodes the single byte encoding of a value type.
    pub fn from_byte(byte: u8) -> Option<ValType> {
        match byte {
            0x7F => Some(ValType::I32),
            0x7E => Some(ValType::I64),
            0x7D => Some(ValType::F32),
            0x7C => Some(ValType::F64),
            _ => None,
        }
    }

    /// True for the two types the interpreter can actually work with.
    pub fn is_integer(self) -> bool {
        matches!(self, ValType::I32 | ValType::I64)
    }

    /// The name used in the text format.
    pub fn name(self) -> &'static str {
        match self {
            ValType::I32 => "i32",
            ValType::I64 => "i64",
            ValType::F32 => "f32",
            ValType::F64 => "f64",
        }
    }
}

impl fmt::Display for ValType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A function signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuncType {
    /// Parameter types, in order.
    pub params: Vec<ValType>,
    /// Result types. WebAssembly 1.0 allows at most one.
    pub results: Vec<ValType>,
}

impl fmt::Display for FuncType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(")?;
        for (i, param) in self.params.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            f.write_str(param.name())?;
        }
        f.write_str(") -> ")?;
        match self.results.len() {
            0 => f.write_str("()"),
            1 => f.write_str(self.results[0].name()),
            _ => {
                f.write_str("(")?;
                for (i, result) in self.results.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    f.write_str(result.name())?;
                }
                f.write_str(")")
            }
        }
    }
}

/// What an import or export refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternKind {
    /// A function.
    Func,
    /// A table.
    Table,
    /// A linear memory.
    Memory,
    /// A global.
    Global,
}

impl ExternKind {
    /// Decodes the single byte kind tag used by the import and export sections.
    pub fn from_byte(byte: u8) -> Option<ExternKind> {
        match byte {
            0x00 => Some(ExternKind::Func),
            0x01 => Some(ExternKind::Table),
            0x02 => Some(ExternKind::Memory),
            0x03 => Some(ExternKind::Global),
            _ => None,
        }
    }

    /// The name used in the text format.
    pub fn name(self) -> &'static str {
        match self {
            ExternKind::Func => "func",
            ExternKind::Table => "table",
            ExternKind::Memory => "memory",
            ExternKind::Global => "global",
        }
    }
}

/// An entry of the export section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    /// The exported name.
    pub name: String,
    /// What kind of thing is exported.
    pub kind: ExternKind,
    /// Index into the corresponding index space.
    pub index: u32,
}

/// An entry of the import section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    /// Module name.
    pub module: String,
    /// Field name inside that module.
    pub name: String,
    /// What kind of thing is imported.
    pub kind: ExternKind,
    /// For function imports, the index into the type section.
    pub type_index: Option<u32>,
}

/// A function defined in this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Func {
    /// Index into [`Module::types`].
    pub type_index: u32,
    /// Declared locals, already flattened out of their run-length encoding.
    pub locals: Vec<ValType>,
    /// The instruction bytes of the body, including its terminating `end`.
    pub body: Vec<u8>,
}

/// A parsed WebAssembly module.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Module {
    /// The type section.
    pub types: Vec<FuncType>,
    /// The import section.
    pub imports: Vec<Import>,
    /// Locally defined functions, in code section order.
    pub funcs: Vec<Func>,
    /// The export section.
    pub exports: Vec<Export>,
    /// The start function, if the module declares one.
    pub start: Option<u32>,
    /// Section ids that were present but skipped.
    pub skipped_sections: Vec<u8>,
    /// Names of custom sections, in order.
    pub custom_sections: Vec<String>,
}

impl Module {
    /// Number of imported functions, which occupy the low function indices.
    pub fn imported_func_count(&self) -> u32 {
        self.imports
            .iter()
            .filter(|import| import.kind == ExternKind::Func)
            .count() as u32
    }

    /// Total size of the function index space.
    pub fn func_count(&self) -> u32 {
        self.imported_func_count() + self.funcs.len() as u32
    }

    /// Resolves a function index into a locally defined function.
    ///
    /// Returns `None` for an out of range index and for imported functions,
    /// which this crate cannot call.
    pub fn local_func(&self, index: u32) -> Option<&Func> {
        let imported = self.imported_func_count();
        if index < imported {
            return None;
        }
        self.funcs.get((index - imported) as usize)
    }

    /// True when `index` refers to an imported function.
    pub fn is_imported_func(&self, index: u32) -> bool {
        index < self.imported_func_count()
    }

    /// The signature of any function, imported or not.
    pub fn func_type(&self, index: u32) -> Option<&FuncType> {
        let type_index = if self.is_imported_func(index) {
            self.imports
                .iter()
                .filter(|import| import.kind == ExternKind::Func)
                .nth(index as usize)
                .and_then(|import| import.type_index)?
        } else {
            self.local_func(index)?.type_index
        };
        self.types.get(type_index as usize)
    }

    /// Looks up an exported function by name and returns its function index.
    pub fn export_func(&self, name: &str) -> Option<u32> {
        self.exports
            .iter()
            .find(|export| export.kind == ExternKind::Func && export.name == name)
            .map(|export| export.index)
    }

    /// A one line summary per export, e.g. `func add: (i32, i32) -> i32`.
    ///
    /// This is what a host would print when asked what a module offers.
    pub fn describe_exports(&self) -> Vec<String> {
        self.exports
            .iter()
            .map(|export| match (export.kind, self.func_type(export.index)) {
                (ExternKind::Func, Some(signature)) => {
                    format!("func {}: {}", export.name, signature)
                }
                (kind, _) => format!("{} {}: #{}", kind.name(), export.name, export.index),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module() -> Module {
        Module {
            types: vec![
                FuncType {
                    params: vec![ValType::I32, ValType::I32],
                    results: vec![ValType::I32],
                },
                FuncType {
                    params: vec![],
                    results: vec![],
                },
            ],
            imports: vec![Import {
                module: "env".to_string(),
                name: "log".to_string(),
                kind: ExternKind::Func,
                type_index: Some(1),
            }],
            funcs: vec![Func {
                type_index: 0,
                locals: vec![ValType::I64],
                body: vec![0x0B],
            }],
            exports: vec![
                Export {
                    name: "add".to_string(),
                    kind: ExternKind::Func,
                    index: 1,
                },
                Export {
                    name: "mem".to_string(),
                    kind: ExternKind::Memory,
                    index: 0,
                },
            ],
            start: None,
            skipped_sections: vec![5],
            custom_sections: vec!["name".to_string()],
        }
    }

    #[test]
    fn value_types_decode() {
        assert_eq!(ValType::from_byte(0x7F), Some(ValType::I32));
        assert_eq!(ValType::from_byte(0x7C), Some(ValType::F64));
        assert_eq!(ValType::from_byte(0x40), None);
        assert!(ValType::I64.is_integer());
        assert!(!ValType::F32.is_integer());
        assert_eq!(ValType::I32.to_string(), "i32");
    }

    #[test]
    fn signatures_display_readably() {
        let signature = FuncType {
            params: vec![ValType::I32, ValType::I64],
            results: vec![ValType::I32],
        };
        assert_eq!(signature.to_string(), "(i32, i64) -> i32");

        let void = FuncType {
            params: vec![],
            results: vec![],
        };
        assert_eq!(void.to_string(), "() -> ()");
    }

    #[test]
    fn function_indices_account_for_imports() {
        let m = module();
        assert_eq!(m.imported_func_count(), 1);
        assert_eq!(m.func_count(), 2);
        assert!(m.is_imported_func(0));
        assert!(!m.is_imported_func(1));
        // Index 0 is the import, so it has no body here.
        assert!(m.local_func(0).is_none());
        assert_eq!(m.local_func(1).unwrap().type_index, 0);
        assert!(m.local_func(2).is_none());
    }

    #[test]
    fn signatures_resolve_for_imports_and_locals() {
        let m = module();
        assert_eq!(m.func_type(0).unwrap().to_string(), "() -> ()");
        assert_eq!(m.func_type(1).unwrap().to_string(), "(i32, i32) -> i32");
        assert!(m.func_type(9).is_none());
    }

    #[test]
    fn exports_resolve_by_name_and_kind() {
        let m = module();
        assert_eq!(m.export_func("add"), Some(1));
        assert_eq!(m.export_func("mem"), None, "a memory is not a function");
        assert_eq!(m.export_func("nope"), None);
        assert_eq!(
            m.describe_exports(),
            vec![
                "func add: (i32, i32) -> i32".to_string(),
                "memory mem: #0".to_string()
            ]
        );
    }

    #[test]
    fn extern_kinds_decode() {
        assert_eq!(ExternKind::from_byte(0x00), Some(ExternKind::Func));
        assert_eq!(ExternKind::from_byte(0x03), Some(ExternKind::Global));
        assert_eq!(ExternKind::from_byte(0x04), None);
        assert_eq!(ExternKind::Memory.name(), "memory");
    }
}
