use core::convert::TryInto;

use crate::{l2cap::L2capPacket, Data};

pub const ATT_READ_BY_GROUP_TYPE_REQUEST_OPCODE: u8 = 0x10;
const ATT_READ_BY_GROUP_TYPE_RESPONSE_OPCODE: u8 = 0x11;
const ATT_ERROR_RESPONSE_OPCODE: u8 = 0x01;
pub const ATT_READ_BY_TYPE_REQUEST_OPCODE: u8 = 0x08;
const ATT_READ_BY_TYPE_RESPONSE_OPCODE: u8 = 0x09;
pub const ATT_READ_REQUEST_OPCODE: u8 = 0x0a;
const ATT_READ_RESPONSE_OPCODE: u8 = 0x0b;
pub const ATT_WRITE_REQUEST_OPCODE: u8 = 0x12;
const ATT_WRITE_RESPONSE_OPCODE: u8 = 0x13;
pub const ATT_EXCHANGE_MTU_REQUEST_OPCODE: u8 = 0x02;
const ATT_EXCHANGE_MTU_RESPONSE_OPCODE: u8 = 0x03;
pub const ATT_FIND_BY_TYPE_VALUE_REQUEST_OPCODE: u8 = 0x06;
//const ATT_FIND_BY_TYPE_VALUE_RESPONSE_OPCODE: u8 = 0x07;

#[derive(Debug, PartialEq)]
pub enum Uuid {
    Uuid16(u16),
    Uuid128([u8; 16]),
}

impl Uuid {
    pub(crate) fn encode(&self) -> Data {
        let mut data = Data::default();

        match self {
            Uuid::Uuid16(uuid) => {
                data.append(&[(uuid & 0xff) as u8, ((uuid >> 8) & 0xff) as u8]);
            }
            Uuid::Uuid128(uuid) => {
                let mut reversed = uuid.clone();
                reversed.reverse();
                data.append(&reversed);
            }
        }
        data
    }
}

#[derive(Debug)]
pub enum AttErrorCode {
    /// Attempted to use an `Handle` that isn't valid on this server.
    InvalidHandle = 0x01,
    /// Attribute isn't readable.
    ReadNotPermitted = 0x02,
    /// Attribute isn't writable.
    WriteNotPermitted = 0x03,
    /// Attribute PDU is invalid.
    InvalidPdu = 0x04,
    /// Authentication needed before attribute can be read/written.
    InsufficientAuthentication = 0x05,
    /// Server doesn't support this operation.
    RequestNotSupported = 0x06,
    /// Offset was past the end of the attribute.
    InvalidOffset = 0x07,
    /// Authorization needed before attribute can be read/written.
    InsufficientAuthorization = 0x08,
    /// Too many "prepare write" requests have been queued.
    PrepareQueueFull = 0x09,
    /// No attribute found within the specified attribute handle range.
    AttributeNotFound = 0x0A,
    /// Attribute can't be read/written using *Read Key Blob* request.
    AttributeNotLong = 0x0B,
    /// The encryption key in use is too weak to access an attribute.
    InsufficientEncryptionKeySize = 0x0C,
    /// Attribute value has an incorrect length for the operation.
    InvalidAttributeValueLength = 0x0D,
    /// Request has encountered an "unlikely" error and could not be completed.
    UnlikelyError = 0x0E,
    /// Attribute cannot be read/written without an encrypted connection.
    InsufficientEncryption = 0x0F,
    /// Attribute type is an invalid grouping attribute according to a higher-layer spec.
    UnsupportedGroupType = 0x10,
    /// Server didn't have enough resources to complete a request.
    InsufficientResources = 0x11,
}

#[derive(Debug)]
pub enum Att {
    ReadByGroupTypeReq {
        start: u16,
        end: u16,
        group_type: Uuid,
    },
    ReadByTypeReq {
        start: u16,
        end: u16,
        attribute_type: Uuid,
    },
    ReadReq {
        handle: u16,
    },
    WriteReq {
        handle: u16,
        data: Data,
    },
    ExchangeMtu {
        mtu: u16,
    },
    FindByTypeValue {
        start_handle: u16,
        end_handle: u16,
        att_type: u16,
        att_value: u16,
    },
}

#[derive(Debug)]
pub enum AttParseError {
    Other,
    UnknownOpcode(u8, Data),
    UnexpectedPayload,
}

pub fn parse_att(packet: L2capPacket) -> Result<Att, AttParseError> {
    let opcode = packet.payload.to_slice()[0];
    let payload = &packet.payload.to_slice()[1..];

    match opcode {
        ATT_READ_BY_GROUP_TYPE_REQUEST_OPCODE => {
            let start_handle = (payload[0] as u16) + ((payload[1] as u16) << 8);
            let end_handle = (payload[2] as u16) + ((payload[3] as u16) << 8);

            let group_type = if payload.len() == 6 {
                Uuid::Uuid16((payload[4] as u16) + ((payload[5] as u16) << 8))
            } else if payload.len() == 20 {
                let uuid = payload[4..21]
                    .try_into()
                    .map_err(|_| AttParseError::Other)?;
                Uuid::Uuid128(uuid)
            } else {
                return Err(AttParseError::UnexpectedPayload);
            };

            Ok(Att::ReadByGroupTypeReq {
                start: start_handle,
                end: end_handle,
                group_type: group_type,
            })
        }
        ATT_READ_BY_TYPE_REQUEST_OPCODE => {
            let start_handle = (payload[0] as u16) + ((payload[1] as u16) << 8);
            let end_handle = (payload[2] as u16) + ((payload[3] as u16) << 8);

            let attribute_type = if payload.len() == 6 {
                Uuid::Uuid16((payload[4] as u16) + ((payload[5] as u16) << 8))
            } else if payload.len() == 20 {
                let uuid = payload[4..21]
                    .try_into()
                    .map_err(|_| AttParseError::Other)?;
                Uuid::Uuid128(uuid)
            } else {
                return Err(AttParseError::UnexpectedPayload);
            };

            Ok(Att::ReadByTypeReq {
                start: start_handle,
                end: end_handle,
                attribute_type,
            })
        }
        ATT_READ_REQUEST_OPCODE => {
            let handle = (payload[0] as u16) + ((payload[1] as u16) << 8);

            Ok(Att::ReadReq { handle })
        }
        ATT_WRITE_REQUEST_OPCODE => {
            let handle = (payload[0] as u16) + ((payload[1] as u16) << 8);
            let mut data = Data::default();
            data.append(&payload[2..]);

            Ok(Att::WriteReq { handle, data })
        }
        ATT_EXCHANGE_MTU_REQUEST_OPCODE => {
            let mtu = (payload[0] as u16) + ((payload[1] as u16) << 8);
            Ok(Att::ExchangeMtu { mtu })
        }
        ATT_FIND_BY_TYPE_VALUE_REQUEST_OPCODE => {
            let start_handle = (payload[0] as u16) + ((payload[1] as u16) << 8);
            let end_handle = (payload[2] as u16) + ((payload[3] as u16) << 8);
            let att_type = (payload[4] as u16) + ((payload[5] as u16) << 8);
            let att_value = (payload[6] as u16) + ((payload[7] as u16) << 8); // only U16 supported here

            Ok(Att::FindByTypeValue {
                start_handle,
                end_handle,
                att_type,
                att_value,
            })
        }
        _ => Err(AttParseError::UnknownOpcode(opcode, Data::new(payload))),
    }
}

#[derive(Debug)]
pub struct AttributeData {
    attribute_handle: u16,
    end_group_handle: u16,
    attribute_value: Uuid,
}

impl AttributeData {
    pub fn new(
        attribute_handle: u16,
        end_group_handle: u16,
        attribute_value: Uuid,
    ) -> AttributeData {
        AttributeData {
            attribute_handle,
            end_group_handle,
            attribute_value,
        }
    }

    pub fn encode(&self) -> Data {
        let mut data = Data::default();
        data.append(&[
            (self.attribute_handle & 0xff) as u8,
            ((self.attribute_handle >> 8) & 0xff) as u8,
        ]);
        data.append(&[
            (self.end_group_handle & 0xff) as u8,
            ((self.end_group_handle >> 8) & 0xff) as u8,
        ]);
        data.append(self.attribute_value.encode().to_slice());
        data
    }
}

#[derive(Debug)]
pub struct AttributePayloadData {
    attribute_handle: u16,
    attribute_value: Data,
}

impl AttributePayloadData {
    pub fn new(attribute_handle: u16, attribute_value: Data) -> AttributePayloadData {
        AttributePayloadData {
            attribute_handle,
            attribute_value,
        }
    }

    pub fn encode(&self) -> Data {
        let mut data = Data::default();
        data.append(&[
            (self.attribute_handle & 0xff) as u8,
            ((self.attribute_handle >> 8) & 0xff) as u8,
        ]);
        data.append(self.attribute_value.to_slice());
        data
    }

    pub fn len(&self) -> usize {
        2 + self.attribute_value.len
    }
}

pub fn att_encode_read_by_group_type_response(attribute_list: &[AttributeData]) -> Data {
    let attribute_data_size = match attribute_list[0].attribute_value {
        Uuid::Uuid16(_) => 6,
        Uuid::Uuid128(_) => 20,
    };

    let mut data = Data::default();
    data.append(&[ATT_READ_BY_GROUP_TYPE_RESPONSE_OPCODE]);
    data.append(&[attribute_data_size]);

    for att_data in attribute_list {
        data.append(att_data.encode().to_slice());
    }

    data
}

pub fn att_encode_error_response(opcode: u8, handle: u16, code: AttErrorCode) -> Data {
    let mut data = Data::default();
    data.append(&[ATT_ERROR_RESPONSE_OPCODE]);
    data.append(&[opcode]);
    data.append(&[(handle & 0xff) as u8, ((handle >> 8) & 0xff) as u8]);
    data.append(&[code as u8]);

    data
}

pub fn att_encode_read_by_type_response(attribute_list: &[AttributePayloadData]) -> Data {
    let attribute_data_size = attribute_list[0].len(); // check if empty

    let mut data = Data::default();
    data.append(&[ATT_READ_BY_TYPE_RESPONSE_OPCODE]);
    data.append(&[attribute_data_size as u8]);

    for att_data in attribute_list {
        data.append(att_data.encode().to_slice());
    }

    data
}

pub fn att_encode_read_response(payload: &Data) -> Data {
    let mut data = Data::default();
    data.append(&[ATT_READ_RESPONSE_OPCODE]);
    data.append(payload.to_slice());

    data
}

pub fn att_encode_write_response() -> Data {
    let mut data = Data::default();
    data.append(&[ATT_WRITE_RESPONSE_OPCODE]);

    data
}

pub fn att_encode_exchange_mtu_response(mtu: u16) -> Data {
    let mut data = Data::default();
    data.append(&[ATT_EXCHANGE_MTU_RESPONSE_OPCODE]);
    data.append(&[(mtu & 0xff) as u8, ((mtu >> 8) & 0xff) as u8]);

    data
}
