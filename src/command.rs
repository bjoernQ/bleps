use crate::Data;

pub const CONTROLLER_OGF: u8 = 0x03;
pub const RESET_OCF: u16 = 0x03;

pub const LE_OGF: u8 = 0x08;
pub const SET_ADVERTISING_PARAMETERS_OCF: u16 = 0x06;
pub const SET_ADVERTISING_DATA_OCF: u16 = 0x08;
pub const SET_ADVERTISE_ENABLE_OCF: u16 = 0x0a;

#[derive(Debug)]
pub struct CommandHeader {
    pub opcode: u16,
    pub len: u8,
}

pub const fn opcode(ogf: u8, ocf: u16) -> u16 {
    ((ogf as u16) << 10) + ocf as u16
}

impl CommandHeader {
    pub fn from_bytes(bytes: &[u8]) -> CommandHeader {
        CommandHeader {
            opcode: ((bytes[1] as u16) << 8) + bytes[0] as u16,
            len: bytes[2],
        }
    }

    pub fn from_ogf_ocf(ogf: u8, ocf: u16, len: u8) -> CommandHeader {
        let opcode = opcode(ogf, ocf);
        CommandHeader { opcode, len }
    }

    pub fn write_into(&self, dst: &mut [u8]) {
        dst[0] = (self.opcode & 0xff) as u8;
        dst[1] = ((self.opcode & 0xff00) >> 8) as u8;
        dst[2] = self.len;
    }

    pub fn ogf(&self) -> u8 {
        ((self.opcode & 0b1111110000000000) >> 10) as u8
    }

    pub fn ocf(&self) -> u16 {
        self.opcode & 0b1111111111
    }
}

pub enum Command {
    Reset,
    LeSetAdvertisingParameters,
    LeSetAdvertisingData { data: Data },
    LeSetAdvertiseEnable(bool),
}

pub fn create_command_data(command: Command) -> Data {
    match command {
        Command::Reset => {
            let mut data = [0u8; 4];
            data[0] = 0x01;
            CommandHeader::from_ogf_ocf(CONTROLLER_OGF, RESET_OCF, 0x00).write_into(&mut data[1..]);
            Data::new(&data)
        }
        Command::LeSetAdvertisingParameters => {
            let mut data = [0u8; 4 + 0xf];
            data[0] = 0x01;
            CommandHeader::from_ogf_ocf(LE_OGF, SET_ADVERTISING_PARAMETERS_OCF, 0x0f)
                .write_into(&mut data[1..]);
            // TODO create this - not hardcoded
            data[4..].copy_from_slice(&[0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0]);
            Data::new(&data)
        }
        Command::LeSetAdvertisingData { ref data } => {
            let mut header = [0u8; 4];
            header[0] = 0x01;
            CommandHeader::from_ogf_ocf(LE_OGF, SET_ADVERTISING_DATA_OCF, data.len as u8)
                .write_into(&mut header[1..]);
            let mut res = Data::new(&header);
            res.append(data.to_slice());
            res
        }
        Command::LeSetAdvertiseEnable(enable) => {
            let mut data = [0u8; 5];
            data[0] = 0x01;
            CommandHeader::from_ogf_ocf(LE_OGF, SET_ADVERTISE_ENABLE_OCF, 0x01)
                .write_into(&mut data[1..]);
            data[4] = if enable { 1 } else { 0 };
            Data::new(&data)
        }
    }
}
