use crate::{Data, HciConnection};

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

impl AclPacket {
    pub fn read(connector: &dyn HciConnection) -> Self {
        let raw_handle_buffer = [connector.read().unwrap(), connector.read().unwrap()];
        let (pb, bc, handle) = Self::decode_raw_handle(raw_handle_buffer);

        let len = u16::from_le_bytes([connector.read().unwrap(), connector.read().unwrap()]);
        log::info!("read len {}", len);
        let data = Data::read(connector, len as usize);

        Self {
            handle,
            boundary_flag: pb,
            bc_flag: bc,
            data,
        }
    }

    #[cfg(feature = "async")]
    pub async fn async_read<T>(connector: &mut T) -> Self
    where
        T: embedded_io_async::Read,
    {
        let mut raw_handle_buffer = [0u8; 2];
        let _raw_handle_len = connector.read(&mut raw_handle_buffer).await.unwrap();
        let (pb, bc, handle) = Self::decode_raw_handle(raw_handle_buffer);

        let mut len_buffer = [0u8; 2];
        let _len_len = connector.read(&mut len_buffer).await.unwrap();
        let len = u16::from_le_bytes(len_buffer);
        let data = Data::async_read(connector, len as usize).await;

        Self {
            handle,
            boundary_flag: pb,
            bc_flag: bc,
            data,
        }
    }

    fn decode_raw_handle(
        raw_handle_buffer: [u8; 2],
    ) -> (BoundaryFlag, ControllerBroadcastFlag, u16) {
        let raw_handle = u16::from_le_bytes(raw_handle_buffer);

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

        (pb, bc, handle)
    }

    // including type (0x02)
    pub fn encode(handle: u16, pb: BoundaryFlag, bc: HostBroadcastFlag, payload: Data) -> Data {
        let mut data = Data::new(&[0x02]);

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

        data.append(payload.as_slice());

        data
    }
}
