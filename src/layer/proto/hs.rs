use rustls::internal::msgs::codec::{self, Codec, Reader};
use rustls::CipherSuite;

use rustls::internal::msgs::{base as r_base, enums as r_enums, handshake as r_handshake};

#[derive(Debug)]
pub struct HandshakeMessagePayload {
    pub typ: r_enums::HandshakeType,
    pub payload: HandshakePayload,
}

impl Codec for HandshakeMessagePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        // encode payload to learn length
        let mut sub: Vec<u8> = Vec::new();
        self.payload.encode(&mut sub);

        // output type, length, and encoded payload
        match self.typ {
            r_enums::HandshakeType::HelloRetryRequest => r_enums::HandshakeType::ServerHello,
            _ => self.typ,
        }
        .encode(bytes);
        codec::u24(sub.len() as u32).encode(bytes);
        bytes.append(&mut sub);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        Self::read_version(r, r_enums::ProtocolVersion::DTLSv1_2)
    }
}

impl HandshakeMessagePayload {
    // taken from rustls
    pub fn read_version(r: &mut Reader, _: rustls::ProtocolVersion) -> Option<Self> {
        use r_enums::{HandshakeType, ProtocolVersion};

        let typ = HandshakeType::read(r)?;
        let len = codec::u24::read(r)?.0 as usize;
        let mut sub = r.sub(len)?;

        let payload = match typ {
            HandshakeType::HelloRequest if sub.left() == 0 => HandshakePayload::HelloRequest,
            HandshakeType::ClientHello => {
                HandshakePayload::ClientHello(ClientHelloPayload::read(&mut sub)?)
            }
            HandshakeType::HelloVerifyRequest => {
                HandshakePayload::HelloVerifyRequest(HelloVerifyRequestPayload::read(&mut sub)?)
            }
            HandshakeType::ServerHello => {
                let version = ProtocolVersion::read(&mut sub)?;
                let random = r_handshake::Random::read(&mut sub)?;

                let mut shp = r_handshake::ServerHelloPayload::read(&mut sub)?;
                shp.legacy_version = version;
                shp.random = random;
                HandshakePayload::ServerHello(shp)
            }
            HandshakeType::Certificate => {
                HandshakePayload::Certificate(r_handshake::CertificatePayload::read(&mut sub)?)
            }
            HandshakeType::ServerKeyExchange => {
                let p = r_handshake::ServerKeyExchangePayload::read(&mut sub)?;
                HandshakePayload::ServerKeyExchange(p)
            }
            HandshakeType::ServerHelloDone => {
                if sub.any_left() {
                    return None;
                }
                HandshakePayload::ServerHelloDone
            }
            HandshakeType::ClientKeyExchange => {
                HandshakePayload::ClientKeyExchange(r_base::Payload::read(&mut sub))
            }
            HandshakeType::CertificateRequest => {
                let p = r_handshake::CertificateRequestPayload::read(&mut sub)?;
                HandshakePayload::CertificateRequest(p)
            }
            HandshakeType::CertificateVerify => HandshakePayload::CertificateVerify(
                r_handshake::DigitallySignedStruct::read(&mut sub)?,
            ),
            HandshakeType::Finished => HandshakePayload::Finished(r_base::Payload::read(&mut sub)),
            HandshakeType::MessageHash => {
                // does not appear on the wire
                return None;
            }
            HandshakeType::HelloRetryRequest => {
                // not legal on wire
                return None;
            }
            _ => HandshakePayload::Unknown(r_base::Payload::read(&mut sub)),
        };

        if sub.any_left() {
            None
        } else {
            Some(Self { typ, payload })
        }
    }
}

// Taken from Rustls, some payloads are taken from Rustls directly, some commented out (because they signal TLSv1.3), ClientHello substituted for a DTLS variant, and HelloVerifyRequest added.
#[derive(Debug)]
pub enum HandshakePayload {
    HelloRequest,
    ClientHello(ClientHelloPayload),
    HelloVerifyRequest(HelloVerifyRequestPayload),
    ServerHello(r_handshake::ServerHelloPayload),
    // HelloRetryRequest(HelloRetryRequest),
    Certificate(r_handshake::CertificatePayload),
    // CertificateTLS13(CertificatePayloadTLS13),
    ServerKeyExchange(r_handshake::ServerKeyExchangePayload),
    CertificateRequest(r_handshake::CertificateRequestPayload),
    // CertificateRequestTLS13(CertificateRequestPayloadTLS13),
    CertificateVerify(r_handshake::DigitallySignedStruct),
    ServerHelloDone,
    // EarlyData,
    // EndOfEarlyData,
    ClientKeyExchange(r_base::Payload),
    // NewSessionTicket(NewSessionTicketPayload),
    // NewSessionTicketTLS13(NewSessionTicketPayloadTLS13),
    // EncryptedExtensions(EncryptedExtensions),
    // KeyUpdate(KeyUpdateRequest),
    Finished(r_base::Payload),
    // CertificateStatus(CertificateStatus),
    // MessageHash(Payload),
    Unknown(r_base::Payload),
}

impl HandshakePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            HandshakePayload::HelloRequest | HandshakePayload::ServerHelloDone => {}
            HandshakePayload::ClientHello(ref x) => x.encode(bytes),
            HandshakePayload::HelloVerifyRequest(ref x) => x.encode(bytes),
            HandshakePayload::ServerHello(ref x) => x.encode(bytes),
            HandshakePayload::Certificate(ref x) => x.encode(bytes),
            HandshakePayload::ServerKeyExchange(ref x) => x.encode(bytes),
            HandshakePayload::ClientKeyExchange(ref x) => x.encode(bytes),
            HandshakePayload::CertificateRequest(ref x) => x.encode(bytes),
            HandshakePayload::CertificateVerify(ref x) => x.encode(bytes),
            HandshakePayload::Finished(ref x) => x.encode(bytes),
            HandshakePayload::Unknown(ref x) => x.encode(bytes),
        }
    }
}

#[derive(Debug)]
pub struct ClientHelloPayload {
    pub client_version: rustls::ProtocolVersion,
    pub random: r_handshake::Random,
    pub session_id: r_handshake::SessionID,
    // max len 225
    pub cookie: Vec<u8>,
    pub cipher_suites: Vec<CipherSuite>,
    pub compression_methods: Vec<r_enums::Compression>,
    pub extensions: Vec<r_handshake::ClientExtension>,
}

impl Codec for ClientHelloPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.client_version.encode(bytes);
        self.random.encode(bytes);
        self.session_id.encode(bytes);
        codec::encode_vec_u8(bytes, &self.cookie);
        codec::encode_vec_u16(bytes, &self.cipher_suites);
        codec::encode_vec_u8(bytes, &self.compression_methods);

        if !self.extensions.is_empty() {
            codec::encode_vec_u16(bytes, &self.extensions);
        }
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let mut ret = Self {
            client_version: rustls::ProtocolVersion::read(r)?,
            random: r_handshake::Random::read(r)?,
            session_id: r_handshake::SessionID::read(r)?,
            cookie: codec::read_vec_u8::<u8>(r)?,
            cipher_suites: codec::read_vec_u16::<CipherSuite>(r)?,
            compression_methods: codec::read_vec_u8::<r_enums::Compression>(r)?,
            extensions: Vec::new(),
        };

        if r.any_left() {
            ret.extensions = codec::read_vec_u16::<r_handshake::ClientExtension>(r)?;
        }

        if r.any_left() || ret.extensions.is_empty() {
            None
        } else {
            Some(ret)
        }
    }
}

#[derive(Debug)]
pub struct HelloVerifyRequestPayload {
    pub server_version: rustls::ProtocolVersion,
    // max len 225
    pub cookie: Vec<u8>,
}

impl Codec for HelloVerifyRequestPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.server_version.encode(bytes);
        codec::encode_vec_u8(bytes, &self.cookie);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let ret = Self {
            server_version: rustls::ProtocolVersion::read(r)?,
            cookie: codec::read_vec_u8::<u8>(r)?,
        };

        if r.any_left() {
            None
        } else {
            Some(ret)
        }
    }
}
