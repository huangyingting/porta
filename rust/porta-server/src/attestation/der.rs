//! A minimal DER reader for the attestation structures the X.509 crate does
//! not decode, such as Android's key description extension.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tlv<'a> {
    /// The first identifier octet's class and constructed bits.
    pub class: u8,
    pub constructed: bool,
    pub tag: u32,
    pub value: &'a [u8],
}

pub const UNIVERSAL: u8 = 0x00;
pub const CONTEXT: u8 = 0x80;
pub const INTEGER: u32 = 2;
pub const BOOLEAN: u32 = 1;
pub const OCTET_STRING: u32 = 4;
pub const ENUMERATED: u32 = 10;
pub const SEQUENCE: u32 = 16;
pub const SET: u32 = 17;

const MAX_DEPTH_BYTES: usize = 1 << 20;

/// Reads one TLV from the front of `input`, returning it and the rest.
pub fn read(input: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    if input.len() > MAX_DEPTH_BYTES {
        return None;
    }
    let (&first, mut rest) = input.split_first()?;
    let class = first & 0xC0;
    let constructed = first & 0x20 != 0;
    let mut tag = u32::from(first & 0x1F);
    if tag == 0x1F {
        tag = 0;
        loop {
            let (&byte, after) = rest.split_first()?;
            rest = after;
            if tag > (u32::MAX >> 7) {
                return None;
            }
            tag = (tag << 7) | u32::from(byte & 0x7F);
            if byte & 0x80 == 0 {
                break;
            }
        }
    }
    let (&length_byte, after) = rest.split_first()?;
    rest = after;
    let length = if length_byte & 0x80 == 0 {
        usize::from(length_byte)
    } else {
        let count = usize::from(length_byte & 0x7F);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let length = rest[..count]
            .iter()
            .fold(0_usize, |length, byte| (length << 8) | usize::from(*byte));
        rest = &rest[count..];
        length
    };
    if rest.len() < length {
        return None;
    }
    let (value, rest) = rest.split_at(length);
    Some((
        Tlv {
            class,
            constructed,
            tag,
            value,
        },
        rest,
    ))
}

/// Every TLV in `input`, which must contain nothing else.
pub fn read_all(mut input: &[u8]) -> Option<Vec<Tlv<'_>>> {
    let mut items = Vec::new();
    while !input.is_empty() {
        let (item, rest) = read(input)?;
        items.push(item);
        input = rest;
        if items.len() > 4096 {
            return None;
        }
    }
    Some(items)
}

impl<'a> Tlv<'a> {
    pub fn is(&self, class: u8, tag: u32) -> bool {
        self.class == class && self.tag == tag
    }

    /// A small non-negative INTEGER or ENUMERATED value.
    pub fn small_unsigned(&self) -> Option<u64> {
        if !(self.is(UNIVERSAL, INTEGER) || self.is(UNIVERSAL, ENUMERATED)) {
            return None;
        }
        let value = self.value;
        if value.is_empty() || value.len() > 9 || value[0] & 0x80 != 0 {
            return None;
        }
        let value = if value.len() == 9 {
            if value[0] != 0 {
                return None;
            }
            &value[1..]
        } else {
            value
        };
        Some(
            value
                .iter()
                .fold(0_u64, |number, byte| (number << 8) | u64::from(*byte)),
        )
    }

    /// The children of a constructed TLV.
    pub fn children(&self) -> Option<Vec<Tlv<'a>>> {
        self.constructed.then(|| read_all(self.value)).flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_short_long_and_high_tag_forms() {
        // [702] EXPLICIT INTEGER 0, then a SEQUENCE with a long length.
        let mut input = vec![0xBF, 0x85, 0x3E, 0x03, 0x02, 0x01, 0x00];
        input.extend([0x30, 0x81, 0x80]);
        input.extend([0x04, 0x7E]);
        input.extend([0xAA; 0x7E]);
        let items = read_all(&input).unwrap();
        assert_eq!(items.len(), 2);
        assert!(items[0].is(CONTEXT, 702) && items[0].constructed);
        assert_eq!(read(items[0].value).unwrap().0.small_unsigned(), Some(0));
        assert!(items[1].is(UNIVERSAL, SEQUENCE));
        assert_eq!(items[1].children().unwrap()[0].value.len(), 0x7E);
    }

    #[test]
    fn rejects_truncation_and_odd_integers() {
        assert!(read(&[0x04, 0x05, 1, 2]).is_none());
        assert!(read(&[0x30, 0x80]).is_none());
        assert!(read(&[0xBF]).is_none());
        let negative = read(&[0x02, 0x01, 0xFF]).unwrap().0;
        assert_eq!(negative.small_unsigned(), None);
    }
}
