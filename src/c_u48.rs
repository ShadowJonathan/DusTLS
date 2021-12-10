use rustls::internal::msgs::codec::{Codec, Reader};

// Make a distinct type for u48, even though it's a u64 underneath
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
pub struct u48(pub u64);

impl u48 {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let [a, b, c, d, e, f]: [u8; 6] = bytes.try_into().ok()?;
        Some(Self(u64::from_be_bytes([0, 0, a, b, c, d, e, f])))
    }
}

impl From<u48> for u64 {
    #[inline]
    fn from(v: u48) -> Self {
        v.0 as Self
    }
}

impl TryInto<u48> for u64 {
    type Error = ();

    fn try_into(self) -> Result<u48, Self::Error> {
        if self > 0xffff_ffff_ffffu64 {
            return Err(())
        } else {
            return Ok(u48(self))
        }
    }
}

impl Codec for u48 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let be_bytes = u64::to_be_bytes(self.0);
        bytes.extend_from_slice(&be_bytes[2..])
    }

    fn read(r: &mut Reader) -> Option<Self> {
        r.take(6).and_then(Self::decode)
    }
}