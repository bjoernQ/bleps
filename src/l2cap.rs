use crate::{acl::AclPacket, Data};

#[derive(Debug)]
pub struct L2capPacket {
    pub length: u16,
    pub channel: u16,
    pub payload: Data,
}

#[derive(Debug)]
pub enum L2capParseError {
    Other,
}

pub fn parse_l2cap(packet: AclPacket) -> Result<(u16, L2capPacket), L2capParseError> {
    let data = packet.data.to_slice();
    let length = (data[0] as u16) + ((data[1] as u16) << 8);
    let channel = (data[2] as u16) + ((data[3] as u16) << 8);
    let payload = Data::new(&data[4..]);

    Ok((
        packet.handle,
        L2capPacket {
            length,
            channel,
            payload,
        },
    ))
}

pub fn encode_l2cap(att_data: Data) -> Data {
    let mut data = Data::default();
    data.append(&[0, 0]); // len set later
    data.append(&[0x04, 0x00]); // channel
    data.append(att_data.to_slice());

    let len = data.len - 4;
    data.set(0, (len & 0xff) as u8);
    data.set(1, ((len >> 8) & 0xff) as u8);

    data
}
