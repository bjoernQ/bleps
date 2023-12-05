#![no_std]
#![feature(assert_matches)]
#![cfg_attr(feature = "async", feature(async_fn_in_trait))]
#![cfg_attr(feature = "async", allow(async_fn_in_trait))]
#![cfg_attr(feature = "async", allow(incomplete_features))]

use core::cell::RefCell;

use acl::AclPacket;
use command::{
    opcode, Command, INFORMATIONAL_OGF, LONG_TERM_KEY_REQUEST_REPLY_OCF, READ_BD_ADDR_OCF,
    SET_ADVERTISE_ENABLE_OCF, SET_ADVERTISING_DATA_OCF, SET_SCAN_RSP_DATA_OCF,
};
use command::{LE_OGF, SET_ADVERTISING_PARAMETERS_OCF};
use embedded_io_blocking::{Read, Write};
use event::EventType;

pub mod acl;
pub mod att;
pub mod l2cap;

pub mod command;
pub mod event;

pub mod ad_structure;

pub mod attribute;
pub mod attribute_server;

pub mod crypto;
pub mod sm;

#[cfg(feature = "async")]
pub mod async_attribute_server;

#[cfg(feature = "macros")]
pub use bleps_macros::gatt;

use command::CONTROLLER_OGF;
use command::RESET_OCF;

const TIMEOUT_MILLIS: u64 = 1000;

#[derive(Debug)]
pub enum Error {
    Timeout,
    Failed(u8),
}

#[cfg(feature = "defmt")]
impl defmt::Format for Error {
    fn format(&self, fmt: defmt::Formatter) {
        match self {
            Error::Timeout => {
                defmt::write!(fmt, "Timeout")
            }
            Error::Failed(value) => {
                defmt::write!(fmt, "Failed({})", value)
            }
        }
    }
}

#[derive(Debug)]
pub enum PollResult {
    Event(EventType),
    AsyncData(AclPacket),
}

#[derive(Clone, Copy)]
pub struct Data {
    pub data: [u8; 256],
    pub len: usize,
}

impl Data {
    pub fn new(bytes: &[u8]) -> Data {
        let mut data = [0u8; 256];
        data[..bytes.len()].copy_from_slice(bytes);
        Data {
            data,
            len: bytes.len(),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[0..self.len]
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        &mut self.data[self.len..]
    }

    pub fn set_len(&mut self, new_len: usize) {
        self.len = if new_len > self.data.len() {
            self.data.len()
        } else {
            new_len
        };
    }

    pub fn append_len(&mut self, extra_len: usize) {
        self.set_len(self.len + extra_len);
    }

    pub fn limit_len(&mut self, max_len: usize) {
        if self.len > max_len {
            self.len = max_len;
        }
    }

    pub fn subdata_from(&self, from: usize) -> Data {
        let mut data = [0u8; 256];
        let new_len = self.len - from;
        data[..new_len].copy_from_slice(&self.data[from..(from + new_len)]);
        Data { data, len: new_len }
    }

    pub fn append(&mut self, bytes: &[u8]) {
        self.data[self.len..(self.len + bytes.len())].copy_from_slice(bytes);
        self.len += bytes.len();
    }

    pub fn append_value<T: Sized + 'static>(&mut self, value: T) {
        let slice = unsafe {
            core::slice::from_raw_parts(&value as *const _ as *const _, core::mem::size_of::<T>())
        };

        #[cfg(target_endian = "little")]
        self.append(slice);

        #[cfg(target_endian = "big")]
        {
            let top = slice.len() - 1;
            for (index, byte) in slice.iter().enumerate() {
                self.set(top - index, *byte);
            }
            self.append_len(slice.len());
        }
    }

    pub fn set(&mut self, index: usize, byte: u8) {
        self.data[index] = byte;
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

impl Default for Data {
    fn default() -> Self {
        Data::new(&[])
    }
}

impl core::fmt::Debug for Data {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:x?}", &self.data[..self.len]).expect("Failed to format Data");
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AdvertisingType {
    AdvInd = 0x00,
    AdvDirectInd = 0x01,
    AdvScanInd = 0x02,
    AdvNonConnInd = 0x03,
    AdvDirectIndLowDuty = 0x04,
}

#[derive(Debug, Clone, Copy)]
pub enum OwnAddressType {
    Public = 0x00,
    Random = 0x01,
    ResolvablePrivateAddress = 0x02,
    ResolvablePrivateAddressFromIRK = 0x03,
}

#[derive(Debug, Clone, Copy)]
pub enum PeerAddressType {
    Public = 0x00,
    Random = 0x01,
}

#[derive(Debug, Clone, Copy)]
pub enum AdvertisingChannelMapBits {
    Channel37 = 0b001,
    Channel38 = 0b010,
    Channel39 = 0b100,
}

#[derive(Debug, Clone, Copy)]
pub enum AdvertisingFilterPolicy {
    All = 0x00,
    FilteredScanAllConnect = 0x01,
    AllScanFilteredConnect = 0x02,
    Filtered = 0x03,
}

#[derive(Debug, Clone, Copy)]
pub struct AdvertisingParameters {
    pub advertising_interval_min: u16,
    pub advertising_interval_max: u16,
    pub advertising_type: AdvertisingType,
    pub own_address_type: OwnAddressType,
    pub peer_address_type: PeerAddressType,
    pub peer_address: [u8; 6],
    pub advertising_channel_map: u8,
    pub filter_policy: AdvertisingFilterPolicy,
}

const PACKET_TYPE_COMMAND: u8 = 0x01;
const PACKET_TYPE_ASYNC_DATA: u8 = 0x02;
const PACKET_TYPE_EVENT: u8 = 0x04;

pub struct Ble<'a> {
    connector: &'a dyn HciConnection,
}

impl<'a> Ble<'a> {
    pub fn new(connector: &'a dyn HciConnection) -> Ble<'a> {
        Ble { connector }
    }

    pub fn init(&mut self) -> Result<(), Error>
    where
        Self: Sized,
    {
        self.cmd_reset()?;
        Ok(())
    }

    pub fn cmd_reset(&mut self) -> Result<EventType, Error>
    where
        Self: Sized,
    {
        self.write_bytes(Command::Reset.encode().as_slice());
        self.wait_for_command_complete(CONTROLLER_OGF, RESET_OCF)?
            .check_command_completed()
    }

    pub fn cmd_set_le_advertising_parameters(&mut self) -> Result<EventType, Error>
    where
        Self: Sized,
    {
        self.write_bytes(Command::LeSetAdvertisingParameters.encode().as_slice());
        self.wait_for_command_complete(LE_OGF, SET_ADVERTISING_PARAMETERS_OCF)?
            .check_command_completed()
    }

    pub fn cmd_set_le_advertising_parameters_custom(
        &mut self,
        params: &AdvertisingParameters,
    ) -> Result<EventType, Error>
    where
        Self: Sized,
    {
        self.write_bytes(
            Command::LeSetAdvertisingParametersCustom(params)
                .encode()
                .as_slice(),
        );
        self.wait_for_command_complete(LE_OGF, SET_ADVERTISING_PARAMETERS_OCF)?
            .check_command_completed()
    }

    pub fn cmd_set_le_advertising_data(&mut self, data: Data) -> Result<EventType, Error>
    where
        Self: Sized,
    {
        self.write_bytes(Command::LeSetAdvertisingData { data }.encode().as_slice());
        self.wait_for_command_complete(LE_OGF, SET_ADVERTISING_DATA_OCF)?
            .check_command_completed()
    }

    pub fn cmd_set_le_scan_rsp_data(&mut self, data: Data) -> Result<EventType, Error>
    where
        Self: Sized,
    {
        self.write_bytes(Command::LeSetScanRspData { data }.encode().as_slice());
        self.wait_for_command_complete(LE_OGF, SET_SCAN_RSP_DATA_OCF)?
            .check_command_completed()
    }

    pub fn cmd_set_le_advertise_enable(&mut self, enable: bool) -> Result<EventType, Error>
    where
        Self: Sized,
    {
        self.write_bytes(Command::LeSetAdvertiseEnable(enable).encode().as_slice());
        self.wait_for_command_complete(LE_OGF, SET_ADVERTISE_ENABLE_OCF)?
            .check_command_completed()
    }

    pub fn cmd_long_term_key_request_reply(
        &mut self,
        handle: u16,
        ltk: u128,
    ) -> Result<EventType, Error>
    where
        Self: Sized,
    {
        log::info!("before, key = {:x}, hanlde = {:x}", ltk, handle);
        self.write_bytes(
            Command::LeLongTermKeyRequestReply { handle, ltk }
                .encode()
                .as_slice(),
        );
        log::info!("done writing command");
        let res = self
            .wait_for_command_complete(LE_OGF, LONG_TERM_KEY_REQUEST_REPLY_OCF)?
            .check_command_completed();
        log::info!("got completion event");

        res
    }

    pub fn cmd_read_br_addr(&mut self) -> Result<[u8; 6], Error>
    where
        Self: Sized,
    {
        self.write_bytes(Command::ReadBrAddr.encode().as_slice());
        let res = self
            .wait_for_command_complete(INFORMATIONAL_OGF, READ_BD_ADDR_OCF)?
            .check_command_completed()?;
        match res {
            EventType::CommandComplete {
                num_packets: _,
                opcode: _,
                data,
            } => Ok(data.as_slice()[1..][..6].try_into().unwrap()),
            _ => Err(Error::Failed(0)),
        }
    }

    fn wait_for_command_complete(&mut self, ogf: u8, ocf: u16) -> Result<EventType, Error>
    where
        Self: Sized,
    {
        let timeout_at = self.connector.millis() + TIMEOUT_MILLIS;
        loop {
            let res = self.poll();
            if res.is_some() {
                log::info!("polled while waiting {:?}", res);
            }

            match res {
                Some(PollResult::Event(event)) => match event {
                    EventType::CommandComplete { opcode: code, .. } if code == opcode(ogf, ocf) => {
                        return Ok(event);
                    }
                    _ => (),
                },
                _ => (),
            }

            if self.connector.millis() > timeout_at {
                return Err(Error::Timeout);
            }
        }
    }

    pub fn poll(&mut self) -> Option<PollResult>
    where
        Self: Sized,
    {
        // poll & process input
        let packet_type = self.connector.read();

        match packet_type {
            Some(packet_type) => match packet_type {
                PACKET_TYPE_COMMAND => {}
                PACKET_TYPE_ASYNC_DATA => {
                    let acl_packet = AclPacket::read(self.connector);
                    return Some(PollResult::AsyncData(acl_packet));
                }
                PACKET_TYPE_EVENT => {
                    let event = EventType::read(self.connector);
                    return Some(PollResult::Event(event));
                }
                _ => {
                    // this is a serious error
                    panic!("Unknown packet type {}", packet_type);
                }
            },
            None => {}
        }

        None
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.connector.write(*b);
        }
    }
}

impl Data {
    fn read(connector: &dyn HciConnection, len: usize) -> Self {
        let mut data = [0u8; 256];
        for i in 0..len {
            loop {
                match connector.read() {
                    Some(byte) => {
                        data[i] = byte;
                        break;
                    }
                    None => {
                        // TODO timeout?
                    }
                };
            }
        }
        let mut data = Self::new(&data);
        data.len = len;
        data
    }
}

pub trait HciConnection {
    fn read(&self) -> Option<u8>;

    fn write(&self, data: u8);

    fn millis(&self) -> u64;
}

pub struct HciConnector<T>
where
    T: Read + Write,
{
    hci: RefCell<T>,
    get_millis: fn() -> u64,
}

impl<T> HciConnector<T>
where
    T: Read + Write,
{
    pub fn new(hci: T, get_millis: fn() -> u64) -> HciConnector<T> {
        HciConnector {
            hci: RefCell::new(hci),
            get_millis,
        }
    }
}

impl<T> HciConnection for HciConnector<T>
where
    T: Read + Write,
{
    fn read(&self) -> Option<u8> {
        let mut buf = [0u8];
        let res = self.hci.borrow_mut().read(&mut buf);
        match res {
            Ok(len) if len == 1 => Some(buf[0]),
            _ => None,
        }
    }

    fn write(&self, data: u8) {
        self.hci.borrow_mut().write(&[data]).ok();
    }

    fn millis(&self) -> u64 {
        (self.get_millis)()
    }
}

#[cfg(feature = "async")]
pub mod asynch {
    use super::*;

    pub struct Ble<T>
    where
        T: embedded_io_async::Read + embedded_io_async::Write,
    {
        hci: RefCell<T>,
        get_millis: fn() -> u64,
    }

    impl<T> Ble<T>
    where
        T: embedded_io_async::Read + embedded_io_async::Write,
    {
        pub fn new(hci: T, get_millis: fn() -> u64) -> Ble<T> {
            Ble {
                hci: RefCell::new(hci),
                get_millis,
            }
        }

        fn millis(&self) -> u64 {
            (self.get_millis)()
        }

        pub async fn init(&mut self) -> Result<EventType, Error>
        where
            Self: Sized,
        {
            Ok(self.cmd_reset().await?)
        }

        pub async fn cmd_reset(&mut self) -> Result<EventType, Error>
        where
            Self: Sized,
        {
            self.write_bytes(Command::Reset.encode().as_slice()).await;
            self.wait_for_command_complete(CONTROLLER_OGF, RESET_OCF)
                .await?
                .check_command_completed()
        }

        pub async fn cmd_set_le_advertising_parameters(&mut self) -> Result<EventType, Error>
        where
            Self: Sized,
        {
            self.write_bytes(Command::LeSetAdvertisingParameters.encode().as_slice())
                .await;
            self.wait_for_command_complete(LE_OGF, SET_ADVERTISING_PARAMETERS_OCF)
                .await?
                .check_command_completed()
        }

        pub async fn cmd_set_le_advertising_parameters_custom(
            &mut self,
            params: &AdvertisingParameters,
        ) -> Result<EventType, Error>
        where
            Self: Sized,
        {
            self.write_bytes(
                Command::LeSetAdvertisingParametersCustom(params)
                    .encode()
                    .as_slice(),
            )
            .await;
            self.wait_for_command_complete(LE_OGF, SET_ADVERTISING_PARAMETERS_OCF)
                .await?
                .check_command_completed()
        }

        pub async fn cmd_set_le_advertising_data(&mut self, data: Data) -> Result<EventType, Error>
        where
            Self: Sized,
        {
            self.write_bytes(Command::LeSetAdvertisingData { data }.encode().as_slice())
                .await;
            self.wait_for_command_complete(LE_OGF, SET_ADVERTISING_DATA_OCF)
                .await?
                .check_command_completed()
        }

        pub async fn cmd_set_le_advertise_enable(
            &mut self,
            enable: bool,
        ) -> Result<EventType, Error>
        where
            Self: Sized,
        {
            self.write_bytes(Command::LeSetAdvertiseEnable(enable).encode().as_slice())
                .await;
            self.wait_for_command_complete(LE_OGF, SET_ADVERTISE_ENABLE_OCF)
                .await?
                .check_command_completed()
        }

        pub async fn cmd_long_term_key_request_reply(
            &mut self,
            handle: u16,
            ltk: u128,
        ) -> Result<EventType, Error>
        where
            Self: Sized,
        {
            log::info!("before, key = {:x}, hanlde = {:x}", ltk, handle);
            self.write_bytes(
                Command::LeLongTermKeyRequestReply { handle, ltk }
                    .encode()
                    .as_slice(),
            ).await;
            log::info!("done writing command");
            let res = self
                .wait_for_command_complete(LE_OGF, LONG_TERM_KEY_REQUEST_REPLY_OCF).await?
                .check_command_completed();
            log::info!("got completion event");
    
            res
        }
    
        pub async fn cmd_read_br_addr(&mut self) -> Result<[u8; 6], Error>
        where
            Self: Sized,
        {
            self.write_bytes(Command::ReadBrAddr.encode().as_slice()).await;
            let res = self
                .wait_for_command_complete(INFORMATIONAL_OGF, READ_BD_ADDR_OCF).await?
                .check_command_completed()?;
            match res {
                EventType::CommandComplete {
                    num_packets: _,
                    opcode: _,
                    data,
                } => Ok(data.as_slice()[1..][..6].try_into().unwrap()),
                _ => Err(Error::Failed(0)),
            }
        }        

        pub(crate) async fn wait_for_command_complete(
            &mut self,
            ogf: u8,
            ocf: u16,
        ) -> Result<EventType, Error>
        where
            Self: Sized,
        {
            let timeout_at = self.millis() + TIMEOUT_MILLIS;
            loop {
                let res = self.poll().await;

                match res {
                    Some(PollResult::Event(event)) => match event {
                        EventType::CommandComplete { opcode: code, .. }
                            if code == opcode(ogf, ocf) =>
                        {
                            return Ok(event);
                        }
                        _ => (),
                    },
                    _ => (),
                }

                if self.millis() > timeout_at {
                    return Err(Error::Timeout);
                }
            }
        }

        pub async fn poll(&mut self) -> Option<PollResult>
        where
            Self: Sized,
        {
            // poll & process input
            let packet_type = {
                let mut buffer = [0u8];
                self.hci.borrow_mut().read(&mut buffer).await.unwrap();
                Some(buffer[0])
            };

            match packet_type {
                Some(packet_type) => match packet_type {
                    PACKET_TYPE_COMMAND => {}
                    PACKET_TYPE_ASYNC_DATA => {
                        let acl_packet = AclPacket::async_read(&mut *self.hci.borrow_mut()).await;
                        return Some(PollResult::AsyncData(acl_packet));
                    }
                    PACKET_TYPE_EVENT => {
                        let event = EventType::async_read(&mut *self.hci.borrow_mut()).await;
                        return Some(PollResult::Event(event));
                    }
                    _ => {
                        // this is an serious error
                        panic!("Unknown packet type {}", packet_type);
                    }
                },
                None => {}
            }

            None
        }

        pub(crate) async fn write_bytes(&mut self, bytes: &[u8]) {
            self.hci.borrow_mut().write(bytes).await.unwrap();
        }
    }

    impl Data {
        pub(crate) async fn async_read<T>(mut connector: T, len: usize) -> Self
        where
            T: embedded_io_async::Read,
        {
            let mut idx = 0;
            let mut data = [0u8; 256];
            loop {
                let l = connector.read(&mut data[idx..][..len]).await.unwrap();
                idx += l;

                if idx >= len {
                    break;
                }

                // TODO timeout?
            }

            let mut data = Self::new(&data);
            data.len = len;
            data
        }
    }
}
