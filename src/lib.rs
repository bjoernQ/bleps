#![no_std]
#![feature(assert_matches)]

use core::cell::RefCell;

use acl::{parse_acl_packet, AclPacket};
use command::{
    create_command_data, opcode, Command, SET_ADVERTISE_ENABLE_OCF, SET_ADVERTISING_DATA_OCF,
};
use command::{LE_OGF, SET_ADVERTISING_PARAMETERS_OCF};
use embedded_io::blocking::{Read, Write};
use event::{parse_event, EventType};

pub mod acl;
pub mod att;
pub mod l2cap;

pub mod command;
pub mod event;

pub mod ad_structure;

pub mod attribute_server;

use command::CONTROLLER_OGF;
use command::RESET_OCF;

const TIMEOUT_MILLIS: u64 = 1000;

#[derive(Debug)]
pub enum Error {
    Timeout,
    Failed(u8),
}

#[derive(Debug)]
pub enum PollResult {
    Event(EventType),
    AsyncData(AclPacket),
}

#[derive(Clone, Copy)]
pub struct Data {
    pub data: [u8; 128],
    pub len: usize,
}

impl Data {
    pub fn new(bytes: &[u8]) -> Data {
        let mut data = [0u8; 128];
        data[..bytes.len()].copy_from_slice(bytes);
        Data {
            data,
            len: bytes.len(),
        }
    }

    pub fn to_slice(&self) -> &[u8] {
        &self.data[0..self.len]
    }

    pub fn subdata_from(&self, from: usize) -> Data {
        let mut data = [0u8; 128];
        let new_len = self.len - from;
        data[..new_len].copy_from_slice(&self.data[from..(from + new_len)]);
        Data { data, len: new_len }
    }

    pub fn append(&mut self, bytes: &[u8]) {
        self.data[self.len..(self.len + bytes.len())].copy_from_slice(bytes);
        self.len += bytes.len();
    }

    pub fn set(&mut self, index: usize, byte: u8) {
        self.data[index] = byte;
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

const PACKET_TYPE_COMMAND: u8 = 0x01;
const PACKET_TYPE_ASYNC_DATA: u8 = 0x02;
const PACKET_TYPE_EVENT: u8 = 0x04;

fn check_command_completed(event: EventType) -> Result<EventType, Error> {
    if let EventType::CommandComplete {
        num_packets: _,
        opcode: _,
        data,
    } = event
    {
        let status = data.to_slice()[0];
        if status != 0 {
            return Err(Error::Failed(status));
        }
    }

    Ok(event)
}

pub struct Ble<'a> {
    connector: &'a dyn HciConnection,
}

impl<'a> Ble<'a> {
    pub fn new(connector: &'a dyn HciConnection) -> Ble<'a> {
        Ble { connector }
    }

    pub fn init(&mut self) -> Result<EventType, Error>
    where
        Self: Sized,
    {
        Ok(self.cmd_reset()?)
    }

    pub fn cmd_reset(&mut self) -> Result<EventType, Error>
    where
        Self: Sized,
    {
        self.write_bytes(create_command_data(Command::Reset).to_slice());
        check_command_completed(self.wait_for_command_complete(CONTROLLER_OGF, RESET_OCF)?)
    }

    pub fn cmd_set_le_advertising_parameters(&mut self) -> Result<EventType, Error>
    where
        Self: Sized,
    {
        self.write_bytes(create_command_data(Command::LeSetAdvertisingParameters).to_slice());
        check_command_completed(
            self.wait_for_command_complete(LE_OGF, SET_ADVERTISING_PARAMETERS_OCF)?,
        )
    }

    pub fn cmd_set_le_advertising_data(&mut self, data: Data) -> Result<EventType, Error>
    where
        Self: Sized,
    {
        self.write_bytes(create_command_data(Command::LeSetAdvertisingData { data }).to_slice());
        check_command_completed(self.wait_for_command_complete(LE_OGF, SET_ADVERTISING_DATA_OCF)?)
    }

    pub fn cmd_set_le_advertise_enable(&mut self, enable: bool) -> Result<EventType, Error>
    where
        Self: Sized,
    {
        self.write_bytes(create_command_data(Command::LeSetAdvertiseEnable(enable)).to_slice());
        check_command_completed(self.wait_for_command_complete(LE_OGF, SET_ADVERTISE_ENABLE_OCF)?)
    }

    fn wait_for_command_complete(&mut self, ogf: u8, ocf: u16) -> Result<EventType, Error>
    where
        Self: Sized,
    {
        let timeout_at = self.connector.millis() + TIMEOUT_MILLIS;
        loop {
            let res = self.poll();

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
                    let acl_packet = parse_acl_packet(self.connector);
                    return Some(PollResult::AsyncData(acl_packet));
                }
                PACKET_TYPE_EVENT => {
                    let event = parse_event(self.connector);
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

    fn write_bytes(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.connector.write(*b);
        }
    }
}

fn read_to_data(connector: &dyn HciConnection, len: usize) -> Data {
    let mut data = [0u8; 128];
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
    let mut data = Data::new(&data);
    data.len = len;
    data
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
