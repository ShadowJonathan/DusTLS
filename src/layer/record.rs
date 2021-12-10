use rustls::{
    internal::msgs::{base::Payload, enums::ContentType},
    ProtocolVersion,
};

use crate::u48;

// A TLS Frame sent over the wire, named DTLSCiphertext in the standard.
pub struct DOpaqueMessage {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub epoch: u16,
    pub seq: u48,
    pub payload: Payload,
}

// A Decrypted TLS frame, named
pub struct DPlainMessage {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub epoch: u16,
    pub seq: u48,
    pub payload: Payload,
}
