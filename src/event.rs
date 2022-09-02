use log::info;

use crate::{read_to_data, Data, HciConnection};

#[derive(Debug)]
pub struct Event {
    code: u8,
    data: Data,
}

#[derive(Debug, Clone, Copy)]
pub enum EventType {
    CommandComplete {
        num_packets: u8,
        opcode: u16,
        data: Data,
    },
    DisconnectComplete {
        handle: u16,
        status: ErrorCode,
        reason: ErrorCode,
    },
    NumberOfCompletedPackets {
        number_of_connection_handles: u8,
        connection_handles: u16, // should be list
        completed_packets: u16,  // should be list
    },
    Unknown,
}

#[derive(Debug, Clone, Copy)]
pub enum ErrorCode {
    Okay = 0x00,
    UnknownHciCommand = 0x01,
    UnknownConnectionIdentifier = 0x02,
    HardwareFailure = 0x03,
    PageTimeout = 0x04,
    AuthenticationFailure = 0x05,
    PinOrKeyMissing = 0x06,
    MemoryCapacityExceeded = 0x07,
    ConnectionTimeout = 0x08,
    ConnectionLimitExceeded = 0x09,
    AclConnectionAlreadyExists = 0x0b,
    CommandDisallowed = 0x0c,
    RemoteUserTerminatedConnection = 0x13,
    // see Error Codes Description in spec
}

impl ErrorCode {
    pub fn from_u8(value: u8) -> ErrorCode {
        match value {
            0x00 => ErrorCode::Okay,
            0x01 => ErrorCode::UnknownHciCommand,
            0x02 => ErrorCode::UnknownConnectionIdentifier,
            0x03 => ErrorCode::HardwareFailure,
            0x04 => ErrorCode::PageTimeout,
            0x05 => ErrorCode::AuthenticationFailure,
            0x06 => ErrorCode::PinOrKeyMissing,
            0x07 => ErrorCode::MemoryCapacityExceeded,
            0x08 => ErrorCode::ConnectionTimeout,
            0x09 => ErrorCode::ConnectionLimitExceeded,
            0x0b => ErrorCode::AclConnectionAlreadyExists,
            0x0c => ErrorCode::CommandDisallowed,
            0x13 => ErrorCode::RemoteUserTerminatedConnection,

            _ => panic!("Unknown error code {}", value),
        }
    }
}

const EVENT_COMMAND_COMPLETE: u8 = 0x0e;
const EVENT_DISCONNECTION_COMPLETE: u8 = 0x05;
const EVENT_NUMBER_OF_COMPLETED_PACKETS: u8 = 0x13;

/// Parses a command and assumes the packet type (0x04) is already read.
pub fn parse_event(connector: &dyn HciConnection) -> EventType {
    let event = read_to_event(connector);

    match event.code {
        EVENT_COMMAND_COMPLETE => {
            let data = event.data.to_slice();
            let num_packets = data[0];
            let opcode = ((data[2] as u16) << 8) + data[1] as u16;
            let data = event.data.subdata_from(3);
            EventType::CommandComplete {
                num_packets,
                opcode,
                data,
            }
        }
        EVENT_DISCONNECTION_COMPLETE => {
            let data = event.data.to_slice();
            let status = data[0];
            let handle = ((data[2] as u16) << 8) + data[1] as u16;
            let reason = data[3];
            let status = ErrorCode::from_u8(status);
            let reason = ErrorCode::from_u8(reason);
            EventType::DisconnectComplete {
                handle,
                status,
                reason,
            }
        }
        EVENT_NUMBER_OF_COMPLETED_PACKETS => {
            let data = event.data.to_slice();
            let num_handles = data[0];
            let connection_handle = ((data[2] as u16) << 8) + data[1] as u16;
            let completed_packet = ((data[4] as u16) << 8) + data[3] as u16;
            EventType::NumberOfCompletedPackets {
                number_of_connection_handles: num_handles,
                connection_handles: connection_handle,
                completed_packets: completed_packet,
            }
        }
        _ => {
            info!(
                "Ignoring unknown event {:02x} data = {:02x?}",
                event.code,
                event.data.to_slice()
            );
            EventType::Unknown
        }
    }
}

fn read_to_event(connector: &dyn HciConnection) -> Event {
    let code = connector.read().unwrap() as u8;
    let len = connector.read().unwrap() as usize;
    let data = read_to_data(connector, len);
    Event { code, data }
}
