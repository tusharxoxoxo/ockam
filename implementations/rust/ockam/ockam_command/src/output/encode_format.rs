use clap::ValueEnum;

/// Data can be encoded in 2 formats
///
///  - Plain: no encoding, the output is simply printed as a string
///  - Hex: the output is serialized using CBOR and the resulting bytes are represented as some HEX text
#[derive(Debug, Clone, ValueEnum, PartialEq, Eq)]
pub enum EncodeFormat {
    Plain,
    Hex,
}
