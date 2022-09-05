use crate::{att::Uuid, Data};

pub const AD_FLAG_LE_LIMITED_DISCOVERABLE: u8 = 0b00000001;
pub const LE_GENERAL_DISCOVERABLE: u8 = 0b00000010;
pub const BR_EDR_NOT_SUPPORTED: u8 = 0b00000100;
pub const SIMUL_LE_BR_CONTROLLER: u8 = 0b00001000;
pub const SIMUL_LE_BR_HOST: u8 = 0b00010000;

#[derive(Debug, Copy, Clone)]
pub enum AdStructure<'a> {
    /// Device flags and baseband capabilities.
    ///
    /// This should be sent if any flags apply to the device. If not (ie. the value sent would be
    /// 0), this may be omitted.
    ///
    /// Must not be used in scan response data.
    Flags(u8),

    ServiceUuids16(&'a [Uuid]),
    ServiceUuids128(&'a [Uuid]),

    /// Service data with 16-bit service UUID.
    ServiceData16 {
        /// The 16-bit service UUID.
        uuid: u16,
        /// The associated service data. May be empty.
        data: &'a [u8],
    },

    /// Sets the full (unabbreviated) device name.
    ///
    /// This will be shown to the user when this device is found.
    CompleteLocalName(&'a str),

    /// Sets the shortened device name.
    ShortenedLocalName(&'a str),

    /// Set manufacturer specific data
    ManufacturerSpecificData {
        company_identifier: u16,
        payload: &'a [u8],
    },

    /// An unknown or unimplemented AD structure stored as raw bytes.
    Unknown {
        /// Type byte.
        ty: u8,
        /// Raw data transmitted after the type.
        data: &'a [u8],
    },
}

impl<'a> AdStructure<'a> {
    pub fn encode(&self) -> Data {
        let mut data = Data::default();
        match self {
            AdStructure::Flags(flags) => {
                data.append(&[0x02, 0x01, *flags]);
            }
            AdStructure::ServiceUuids16(uuids) => {
                data.append(&[(uuids.len() * 2 + 1) as u8, 0x02]);
                for uuid in uuids.iter() {
                    data.append(uuid.encode().to_slice());
                }
            }
            AdStructure::ServiceUuids128(_) => todo!(),
            AdStructure::ServiceData16 { uuid, data } => todo!(
                "Unimplemented AdStructure::ServiceData16 {:?} {:?}",
                uuid,
                data
            ),
            AdStructure::CompleteLocalName(name) => {
                data.append(&[(name.len() + 1) as u8, 0x09]);
                data.append(name.as_bytes());
            }
            AdStructure::ShortenedLocalName(_) => todo!(),
            AdStructure::ManufacturerSpecificData {
                company_identifier,
                payload,
            } => todo!(
                "Unimplemented AdStructure::ManufacturerSpecificData {:?} {:?}",
                company_identifier,
                payload
            ),
            AdStructure::Unknown { ty, data } => todo!("Unimplemented {:?} {:?}", ty, data),
        }

        data
    }
}

pub fn create_advertising_data(ad: &[AdStructure]) -> Data {
    let mut data = Data::default();
    data.append(&[0]);

    for item in ad.iter() {
        data.append(item.encode().to_slice());
    }

    let len = data.len - 1;
    data.set(0, len as u8);

    for _ in 0..(31 - len) {
        data.append(&[0]);
    }

    data
}
