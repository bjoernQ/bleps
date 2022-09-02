use crate::{read_to_data, Data, HciConnection};

#[derive(Debug, Clone, Copy)]
pub struct AclPacket {
    pub handle: u16,
    pub boundary_flag: BoundaryFlag,
    pub bc_flag: ControllerBroadcastFlag,
    pub data: Data,
}

#[derive(Debug, Clone, Copy)]
pub enum BoundaryFlag {
    FirstNonAutoFlushable,
    Continuing,
    FirstAutoFlushable,
    Complete,
}

/// BC flag from controller to host
#[derive(Debug, Clone, Copy)]
pub enum ControllerBroadcastFlag {
    PointToPoint,
    NotParkedState,
    ParkedState,
    Reserved,
}

/// BC flag from host to controller
#[derive(Debug, Clone, Copy)]
pub enum HostBroadcastFlag {
    NoBroadcast,
    ActiveSlaveBroadcast,
    ParkedSlaveBroadcast,
    Reserved,
}

pub fn parse_acl_packet(connector: &dyn HciConnection) -> AclPacket {
    let raw_handle = connector.read().unwrap() as u16 + ((connector.read().unwrap() as u16) << 8);

    let pb = (raw_handle & 0b0011000000000000) >> 12;
    let pb = match pb {
        0b00 => BoundaryFlag::FirstNonAutoFlushable,
        0b01 => BoundaryFlag::Continuing,
        0b10 => BoundaryFlag::FirstAutoFlushable,
        0b11 => BoundaryFlag::Complete,
        _ => panic!("Unexpected boundary flag"),
    };

    let bc = (raw_handle & 0b1100000000000000) >> 14;
    let bc = match bc {
        0b00 => ControllerBroadcastFlag::PointToPoint,
        0b01 => ControllerBroadcastFlag::NotParkedState,
        0b10 => ControllerBroadcastFlag::ParkedState,
        0b11 => ControllerBroadcastFlag::Reserved,
        _ => panic!("Unexpected broadcast flag"),
    };

    let handle = raw_handle & 0b111111111111;

    let len = connector.read().unwrap() as u16 + ((connector.read().unwrap() as u16) << 8);
    let data = read_to_data(connector, len as usize);

    AclPacket {
        handle: handle,
        boundary_flag: pb,
        bc_flag: bc,
        data: data,
    }
}

// including type (0x02)
pub fn encode_acl_packet(
    handle: u16,
    pb: BoundaryFlag,
    bc: HostBroadcastFlag,
    payload: Data,
) -> Data {
    let mut data = Data::default();

    data.append(&[0x02]);

    let mut raw_handle = handle;

    raw_handle |= match pb {
        BoundaryFlag::FirstNonAutoFlushable => 0b00,
        BoundaryFlag::Continuing => 0b01,
        BoundaryFlag::FirstAutoFlushable => 0b10,
        BoundaryFlag::Complete => 0b11,
    } << 12;

    raw_handle |= match bc {
        HostBroadcastFlag::NoBroadcast => 0b00,
        HostBroadcastFlag::ActiveSlaveBroadcast => 0b01,
        HostBroadcastFlag::ParkedSlaveBroadcast => 0b10,
        HostBroadcastFlag::Reserved => 0b11,
    } << 14;

    data.append(&[(raw_handle & 0xff) as u8, ((raw_handle >> 8) & 0xff) as u8]);

    let len = payload.len;
    data.append(&[(len & 0xff) as u8, ((len >> 8) & 0xff) as u8]);

    data.append(payload.to_slice());

    data
}
