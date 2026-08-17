//! The WebAssembly binary format decoder.
//!
//! A `.wasm` file is a magic number, a version, and then a sequence of
//! length-prefixed sections that must appear in increasing id order (custom
//! sections may appear anywhere). This module walks that structure and pulls
//! out everything the interpreter needs.
//!
//! Decoding is strict where strictness is cheap: the magic and version are
//! checked, section order is checked, every section has to consume exactly the
//! number of bytes it declared, LEB128 values have to fit their width, and
//! names have to be valid UTF-8. A malformed module is an `Err`, never a panic.

use crate::leb::{self, LebError};
use crate::module::{Export, ExternKind, Func, FuncType, Import, Module, ValType};
use std::fmt;

/// The four magic bytes at the start of every module.
pub const MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D];

/// The only binary format version there is.
pub const VERSION: u32 = 1;

/// Upper bound on the number of locals a single function may declare.
const MAX_LOCALS: u64 = 100_000;

/// What made a module undecodable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// The file does not start with `\0asm`.
    NotWasm,
    /// The binary format version is not [`VERSION`].
    UnsupportedVersion(u32),
    /// The input ended in the middle of a structure.
    UnexpectedEof,
    /// A LEB128 value was malformed.
    Leb(LebError),
    /// A section id above the highest one the specification defines.
    UnknownSectionId(u8),
    /// Non-custom sections must appear in increasing id order.
    SectionOutOfOrder {
        /// The id of the previous non-custom section.
        previous: u8,
        /// The id that appeared after it.
        found: u8,
    },
    /// A section did not consume exactly the number of bytes it declared.
    SectionSizeMismatch(u8),
    /// A byte that is not a value type.
    InvalidValType(u8),
    /// A type section entry that does not start with `0x60`.
    InvalidFuncType(u8),
    /// An import or export descriptor with an unknown kind byte.
    InvalidExternKind(u8),
    /// A limits descriptor with an unknown flags byte.
    InvalidLimits(u8),
    /// A name that is not valid UTF-8.
    InvalidUtf8,
    /// The function and code sections disagree about how many functions exist.
    FunctionCodeMismatch {
        /// Entries in the function section.
        declared: usize,
        /// Entries in the code section.
        bodies: usize,
    },
    /// A type index that no type section entry answers to.
    TypeIndexOutOfRange(u32),
    /// A function declaring an absurd number of locals.
    TooManyLocals(u64),
    /// A function body that does not end with the `end` opcode.
    MissingEnd,
}

impl fmt::Display for ParseErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseErrorKind::NotWasm => f.write_str("not a WebAssembly module"),
            ParseErrorKind::UnsupportedVersion(v) => {
                write!(f, "unsupported binary format version {}", v)
            }
            ParseErrorKind::UnexpectedEof => f.write_str("unexpected end of module"),
            ParseErrorKind::Leb(err) => write!(f, "{}", err),
            ParseErrorKind::UnknownSectionId(id) => write!(f, "unknown section id {}", id),
            ParseErrorKind::SectionOutOfOrder { previous, found } => write!(
                f,
                "section {} appears after section {}, ids must increase",
                found, previous
            ),
            ParseErrorKind::SectionSizeMismatch(id) => {
                write!(f, "section {} does not match its declared size", id)
            }
            ParseErrorKind::InvalidValType(b) => write!(f, "invalid value type byte {:#04x}", b),
            ParseErrorKind::InvalidFuncType(b) => {
                write!(f, "expected a function type, found byte {:#04x}", b)
            }
            ParseErrorKind::InvalidExternKind(b) => write!(f, "invalid extern kind {:#04x}", b),
            ParseErrorKind::InvalidLimits(b) => write!(f, "invalid limits flags {:#04x}", b),
            ParseErrorKind::InvalidUtf8 => f.write_str("name is not valid UTF-8"),
            ParseErrorKind::FunctionCodeMismatch { declared, bodies } => write!(
                f,
                "function section declares {} functions but the code section has {} bodies",
                declared, bodies
            ),
            ParseErrorKind::TypeIndexOutOfRange(index) => {
                write!(f, "type index {} is out of range", index)
            }
            ParseErrorKind::TooManyLocals(n) => write!(f, "function declares {} locals", n),
            ParseErrorKind::MissingEnd => f.write_str("function body does not end with 'end'"),
        }
    }
}

/// A decoding failure together with the byte offset it was noticed at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Offset into the module bytes.
    pub offset: usize,
    /// What went wrong.
    pub kind: ParseErrorKind,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "at byte {}: {}", self.offset, self.kind)
    }
}

impl std::error::Error for ParseError {}

/// Decodes a module from its binary encoding.
pub fn parse(bytes: &[u8]) -> Result<Module, ParseError> {
    Decoder::new(bytes).module()
}

struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Decoder { bytes, pos: 0 }
    }

    fn err<T>(&self, kind: ParseErrorKind) -> Result<T, ParseError> {
        Err(ParseError {
            offset: self.pos,
            kind,
        })
    }

    fn byte(&mut self) -> Result<u8, ParseError> {
        match self.bytes.get(self.pos) {
            Some(&byte) => {
                self.pos += 1;
                Ok(byte)
            }
            None => self.err(ParseErrorKind::UnexpectedEof),
        }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ParseError> {
        let end = match self.pos.checked_add(len) {
            Some(end) if end <= self.bytes.len() => end,
            _ => return self.err(ParseErrorKind::UnexpectedEof),
        };
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<u32, ParseError> {
        let at = self.pos;
        leb::read_u32(self.bytes, &mut self.pos).map_err(|err| ParseError {
            offset: at,
            kind: ParseErrorKind::Leb(err),
        })
    }

    fn name(&mut self) -> Result<String, ParseError> {
        let len = self.u32()? as usize;
        let at = self.pos;
        let raw = self.take(len)?;
        match std::str::from_utf8(raw) {
            Ok(text) => Ok(text.to_string()),
            Err(_) => Err(ParseError {
                offset: at,
                kind: ParseErrorKind::InvalidUtf8,
            }),
        }
    }

    fn val_type(&mut self) -> Result<ValType, ParseError> {
        let at = self.pos;
        let byte = self.byte()?;
        ValType::from_byte(byte).ok_or(ParseError {
            offset: at,
            kind: ParseErrorKind::InvalidValType(byte),
        })
    }

    fn val_types(&mut self) -> Result<Vec<ValType>, ParseError> {
        let count = self.u32()? as usize;
        let mut out = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            out.push(self.val_type()?);
        }
        Ok(out)
    }

    /// Skips a `limits` descriptor, used by table and memory declarations.
    fn skip_limits(&mut self) -> Result<(), ParseError> {
        let at = self.pos;
        match self.byte()? {
            0x00 => {
                self.u32()?;
            }
            0x01 => {
                self.u32()?;
                self.u32()?;
            }
            other => {
                return Err(ParseError {
                    offset: at,
                    kind: ParseErrorKind::InvalidLimits(other),
                })
            }
        }
        Ok(())
    }

    fn module(&mut self) -> Result<Module, ParseError> {
        let magic = self.take(4)?;
        if magic != MAGIC {
            return Err(ParseError {
                offset: 0,
                kind: ParseErrorKind::NotWasm,
            });
        }
        let at = self.pos;
        let version_bytes = self.take(4)?;
        let version = u32::from_le_bytes([
            version_bytes[0],
            version_bytes[1],
            version_bytes[2],
            version_bytes[3],
        ]);
        if version != VERSION {
            return Err(ParseError {
                offset: at,
                kind: ParseErrorKind::UnsupportedVersion(version),
            });
        }

        let mut module = Module::default();
        let mut declared_types: Vec<u32> = Vec::new();
        let mut last_section: Option<u8> = None;

        while self.pos < self.bytes.len() {
            let id_at = self.pos;
            let id = self.byte()?;
            if id > 12 {
                return Err(ParseError {
                    offset: id_at,
                    kind: ParseErrorKind::UnknownSectionId(id),
                });
            }
            let size = self.u32()? as usize;
            let body_start = self.pos;
            let body_end = match body_start.checked_add(size) {
                Some(end) if end <= self.bytes.len() => end,
                _ => return self.err(ParseErrorKind::UnexpectedEof),
            };

            if id != 0 {
                if let Some(previous) = last_section {
                    if id <= previous {
                        return Err(ParseError {
                            offset: id_at,
                            kind: ParseErrorKind::SectionOutOfOrder { previous, found: id },
                        });
                    }
                }
                last_section = Some(id);
            }

            match id {
                0 => {
                    module.custom_sections.push(self.name()?);
                    self.pos = body_end;
                }
                1 => self.type_section(&mut module)?,
                2 => self.import_section(&mut module)?,
                3 => {
                    let count = self.u32()? as usize;
                    for _ in 0..count {
                        declared_types.push(self.u32()?);
                    }
                }
                7 => self.export_section(&mut module)?,
                8 => module.start = Some(self.u32()?),
                10 => self.code_section(&mut module, &declared_types)?,
                other => {
                    module.skipped_sections.push(other);
                    self.pos = body_end;
                }
            }

            if self.pos != body_end {
                return Err(ParseError {
                    offset: id_at,
                    kind: ParseErrorKind::SectionSizeMismatch(id),
                });
            }
        }

        if declared_types.len() != module.funcs.len() {
            return Err(ParseError {
                offset: self.bytes.len(),
                kind: ParseErrorKind::FunctionCodeMismatch {
                    declared: declared_types.len(),
                    bodies: module.funcs.len(),
                },
            });
        }
        for func in &module.funcs {
            if func.type_index as usize >= module.types.len() {
                return Err(ParseError {
                    offset: self.bytes.len(),
                    kind: ParseErrorKind::TypeIndexOutOfRange(func.type_index),
                });
            }
        }
        Ok(module)
    }

    fn type_section(&mut self, module: &mut Module) -> Result<(), ParseError> {
        let count = self.u32()? as usize;
        for _ in 0..count {
            let at = self.pos;
            let tag = self.byte()?;
            if tag != 0x60 {
                return Err(ParseError {
                    offset: at,
                    kind: ParseErrorKind::InvalidFuncType(tag),
                });
            }
            let params = self.val_types()?;
            let results = self.val_types()?;
            module.types.push(FuncType { params, results });
        }
        Ok(())
    }

    fn import_section(&mut self, module: &mut Module) -> Result<(), ParseError> {
        let count = self.u32()? as usize;
        for _ in 0..count {
            let module_name = self.name()?;
            let field_name = self.name()?;
            let at = self.pos;
            let kind_byte = self.byte()?;
            let kind = ExternKind::from_byte(kind_byte).ok_or(ParseError {
                offset: at,
                kind: ParseErrorKind::InvalidExternKind(kind_byte),
            })?;
            let type_index = match kind {
                ExternKind::Func => Some(self.u32()?),
                ExternKind::Table => {
                    self.byte()?; // reference type
                    self.skip_limits()?;
                    None
                }
                ExternKind::Memory => {
                    self.skip_limits()?;
                    None
                }
                ExternKind::Global => {
                    self.val_type()?;
                    self.byte()?; // mutability
                    None
                }
            };
            module.imports.push(Import {
                module: module_name,
                name: field_name,
                kind,
                type_index,
            });
        }
        Ok(())
    }

    fn export_section(&mut self, module: &mut Module) -> Result<(), ParseError> {
        let count = self.u32()? as usize;
        for _ in 0..count {
            let name = self.name()?;
            let at = self.pos;
            let kind_byte = self.byte()?;
            let kind = ExternKind::from_byte(kind_byte).ok_or(ParseError {
                offset: at,
                kind: ParseErrorKind::InvalidExternKind(kind_byte),
            })?;
            let index = self.u32()?;
            module.exports.push(Export { name, kind, index });
        }
        Ok(())
    }

    fn code_section(&mut self, module: &mut Module, declared: &[u32]) -> Result<(), ParseError> {
        let count = self.u32()? as usize;
        for index in 0..count {
            let size = self.u32()? as usize;
            let entry_start = self.pos;
            let entry_end = match entry_start.checked_add(size) {
                Some(end) if end <= self.bytes.len() => end,
                _ => return self.err(ParseErrorKind::UnexpectedEof),
            };

            let groups = self.u32()? as usize;
            let mut locals: Vec<ValType> = Vec::new();
            let mut total: u64 = 0;
            for _ in 0..groups {
                let at = self.pos;
                let repeat = u64::from(self.u32()?);
                let ty = self.val_type()?;
                total += repeat;
                if total > MAX_LOCALS {
                    return Err(ParseError {
                        offset: at,
                        kind: ParseErrorKind::TooManyLocals(total),
                    });
                }
                locals.extend(std::iter::repeat_n(ty, repeat as usize));
            }

            if self.pos > entry_end {
                return self.err(ParseErrorKind::UnexpectedEof);
            }
            let body = self.take(entry_end - self.pos)?.to_vec();
            if body.last() != Some(&0x0B) {
                return Err(ParseError {
                    offset: entry_end,
                    kind: ParseErrorKind::MissingEnd,
                });
            }

            let type_index = match declared.get(index) {
                Some(&type_index) => type_index,
                None => {
                    return Err(ParseError {
                        offset: entry_start,
                        kind: ParseErrorKind::FunctionCodeMismatch {
                            declared: declared.len(),
                            bodies: count,
                        },
                    })
                }
            };
            module.funcs.push(Func {
                type_index,
                locals,
                body,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(module (func (export "id") (param i32) (result i32) local.get 0))`
    /// assembled by hand, one byte per line group.
    fn identity_module() -> Vec<u8> {
        vec![
            0x00, 0x61, 0x73, 0x6D, // magic "\0asm"
            0x01, 0x00, 0x00, 0x00, // version 1
            // type section: one type, (i32) -> i32
            0x01, 0x06, 0x01, 0x60, 0x01, 0x7F, 0x01, 0x7F,
            // function section: one function using type 0
            0x03, 0x02, 0x01, 0x00,
            // export section: "id" is function 0
            0x07, 0x06, 0x01, 0x02, 0x69, 0x64, 0x00, 0x00,
            // code section: one body, no locals, local.get 0, end
            0x0A, 0x06, 0x01, 0x04, 0x00, 0x20, 0x00, 0x0B,
        ]
    }

    #[test]
    fn parses_a_minimal_module() {
        let m = parse(&identity_module()).expect("module should parse");
        assert_eq!(m.types.len(), 1);
        assert_eq!(m.types[0].to_string(), "(i32) -> i32");
        assert_eq!(m.funcs.len(), 1);
        assert_eq!(m.funcs[0].locals.len(), 0);
        assert_eq!(m.funcs[0].body, vec![0x20, 0x00, 0x0B]);
        assert_eq!(m.export_func("id"), Some(0));
        assert_eq!(m.describe_exports(), vec!["func id: (i32) -> i32"]);
        assert_eq!(m.start, None);
    }

    #[test]
    fn rejects_bad_headers() {
        assert_eq!(parse(b"").unwrap_err().kind, ParseErrorKind::UnexpectedEof);
        assert_eq!(
            parse(b"\0asm").unwrap_err().kind,
            ParseErrorKind::UnexpectedEof
        );
        assert_eq!(
            parse(b"NOPE\x01\0\0\0").unwrap_err().kind,
            ParseErrorKind::NotWasm
        );
        let mut bytes = identity_module();
        bytes[4] = 0x02;
        assert_eq!(
            parse(&bytes).unwrap_err().kind,
            ParseErrorKind::UnsupportedVersion(2)
        );
    }

    #[test]
    fn rejects_sections_out_of_order() {
        let mut bytes = identity_module()[..8].to_vec();
        // export section (7) before the type section (1)
        bytes.extend_from_slice(&[0x07, 0x01, 0x00]);
        bytes.extend_from_slice(&[0x01, 0x01, 0x00]);
        assert_eq!(
            parse(&bytes).unwrap_err().kind,
            ParseErrorKind::SectionOutOfOrder {
                previous: 7,
                found: 1
            }
        );
    }

    #[test]
    fn rejects_a_lying_section_size() {
        let mut bytes = identity_module();
        // The type section really needs 6 bytes; claim it needs 7.
        bytes[9] = 0x07;
        let err = parse(&bytes).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::SectionSizeMismatch(1));
    }

    #[test]
    fn rejects_unknown_section_ids() {
        let mut bytes = identity_module()[..8].to_vec();
        bytes.extend_from_slice(&[0x0D, 0x00]);
        assert_eq!(
            parse(&bytes).unwrap_err().kind,
            ParseErrorKind::UnknownSectionId(13)
        );
    }

    #[test]
    fn rejects_a_body_without_end() {
        let mut bytes = identity_module();
        let last = bytes.len() - 1;
        bytes[last] = 0x1A; // drop, instead of end
        assert_eq!(parse(&bytes).unwrap_err().kind, ParseErrorKind::MissingEnd);
    }

    #[test]
    fn rejects_mismatched_function_and_code_sections() {
        let mut bytes = identity_module();
        // Say there are two functions but keep a single body.
        bytes[18] = 0x02; // function section count
        bytes[19] = 0x00;
        bytes.insert(20, 0x00);
        bytes[17] = 0x03; // grow the declared section size
        let err = parse(&bytes).unwrap_err();
        assert_eq!(
            err.kind,
            ParseErrorKind::FunctionCodeMismatch {
                declared: 2,
                bodies: 1
            }
        );
    }

    #[test]
    fn rejects_an_out_of_range_type_index() {
        let mut bytes = identity_module();
        bytes[19] = 0x05; // function section refers to type 5
        assert_eq!(
            parse(&bytes).unwrap_err().kind,
            ParseErrorKind::TypeIndexOutOfRange(5)
        );
    }

    #[test]
    fn records_custom_and_skipped_sections() {
        let mut bytes = identity_module();
        // A custom section named "name" appended at the end.
        bytes.extend_from_slice(&[0x00, 0x05, 0x04, 0x6E, 0x61, 0x6D, 0x65]);
        // A memory section declaring one memory with min 1 page.
        let insert_at = 20; // right after the function section
        let memory = [0x05, 0x03, 0x01, 0x00, 0x01];
        bytes.splice(insert_at..insert_at, memory);
        let m = parse(&bytes).expect("module should still parse");
        assert_eq!(m.custom_sections, vec!["name".to_string()]);
        assert_eq!(m.skipped_sections, vec![5]);
    }

    #[test]
    fn parses_imports_and_offsets_function_indices() {
        let bytes = vec![
            0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
            // type section: two types, () -> () and (i32) -> i32
            0x01, 0x09, 0x02, 0x60, 0x00, 0x00, 0x60, 0x01, 0x7F, 0x01, 0x7F,
            // import section: env.log as a function of type 0
            0x02, 0x0B, 0x01, 0x03, 0x65, 0x6E, 0x76, 0x03, 0x6C, 0x6F, 0x67, 0x00, 0x00,
            // function section: one local function of type 1
            0x03, 0x02, 0x01, 0x01,
            // code section: local.get 0, end
            0x0A, 0x06, 0x01, 0x04, 0x00, 0x20, 0x00, 0x0B,
        ];
        let m = parse(&bytes).expect("module should parse");
        assert_eq!(m.imports.len(), 1);
        assert_eq!(m.imports[0].module, "env");
        assert_eq!(m.imports[0].name, "log");
        assert_eq!(m.imported_func_count(), 1);
        assert_eq!(m.func_count(), 2);
        assert!(m.is_imported_func(0));
        assert_eq!(m.func_type(0).unwrap().to_string(), "() -> ()");
        assert_eq!(m.func_type(1).unwrap().to_string(), "(i32) -> i32");
    }

    #[test]
    fn parses_locals() {
        let bytes = vec![
            0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type: () -> ()
            0x03, 0x02, 0x01, 0x00, // one function
            // code: two local groups (2 x i32, 1 x i64), then end
            0x0A, 0x08, 0x01, 0x06, 0x02, 0x02, 0x7F, 0x01, 0x7E, 0x0B,
        ];
        let m = parse(&bytes).expect("module should parse");
        assert_eq!(
            m.funcs[0].locals,
            vec![ValType::I32, ValType::I32, ValType::I64]
        );
        assert_eq!(m.funcs[0].body, vec![0x0B]);
    }

    #[test]
    fn error_display_includes_the_offset() {
        let err = parse(b"NOPE\x01\0\0\0").unwrap_err();
        assert_eq!(err.to_string(), "at byte 0: not a WebAssembly module");
    }
}
