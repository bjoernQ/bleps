// Use with the esp32s3-serial-hci

use std::time::Duration;

use bleps::{
    ad_structure::{
        create_advertising_data, AdStructure, BR_EDR_NOT_SUPPORTED, LE_GENERAL_DISCOVERABLE,
    },
    attribute_server::{AttributeServer, WorkResult},
    Ble, HciConnector,
};
use bleps_macros::gatt;
use embedded_io::{
    blocking::{Read, Write},
    Error, Io,
};

fn main() {
    env_logger::init();

    if std::env::args().len() != 2 {
        println!("Provide the serial port as the one and only command line argument.");
        return;
    }

    let args: Vec<String> = std::env::args().collect();

    let port = serialport::new(&args[1], 115_200)
        .timeout(Duration::from_millis(100))
        .open()
        .expect("Failed to open port");

    println!("Reset the target");

    let mut serial = embedded_io::adapters::FromStd::new(port);

    let mut buffer = [0u8; 1];

    loop {
        match serial.read(&mut buffer) {
            Ok(_len) => {
                if buffer[0] == 0xff {
                    break;
                }
            }
            Err(_) => (),
        }
    }

    println!("Connected");

    loop {
        let connector = BleConnector::new(&mut serial);
        let hci = HciConnector::new(connector, current_millis);
        let mut ble = Ble::new(&hci);

        println!("{:?}", ble.init());
        println!("{:?}", ble.cmd_set_le_advertising_parameters());
        println!(
            "{:?}",
            ble.cmd_set_le_advertising_data(create_advertising_data(&[
                AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
                AdStructure::ServiceUuids16(&[Uuid::Uuid16(0x1809)]),
                AdStructure::CompleteLocalName("BLEPS"),
            ]))
        );
        println!("{:?}", ble.cmd_set_le_advertise_enable(true));

        println!("started advertising");

        let mut rf = || Data::new(b"Hello Bare-Metal BLE");
        let mut wf = |offset, data: Data| {
            println!("RECEIVED: Offset {}, data {:x?}", offset, data.to_slice());
        };

        let mut wf2 = |_offset, _data| {};

        gatt!([service {
            uuid: "937312e0-2354-11eb-9f10-fbc30a62cf38",
            characteristics: [
                characteristic {
                    uuid: "937312e0-2354-11eb-9f10-fbc30a62cf38",
                    read: rf,
                    write: wf,
                },
                characteristic {
                    uuid: "957312e0-2354-11eb-9f10-fbc30a62cf38",
                    write: wf2,
                },
            ],
        },]);

        let mut srv = AttributeServer::new(&mut ble, &mut gatt_attributes);

        loop {
            match srv.do_work() {
                Ok(res) => {
                    if let WorkResult::GotDisconnected = res {
                        println!("Received disconnect");
                        break;
                    }
                }
                Err(err) => {
                    println!("{:x?}", err);
                }
            }
        }
    }
}

fn current_millis() -> u64 {
    std::time::Instant::now().elapsed().as_millis() as u64
}

pub struct BleConnector<'a, T> {
    connection: &'a mut T,
}

impl<'a, T> BleConnector<'a, T>
where
    T: Read + Write,
{
    fn new(connection: &'a mut T) -> Self {
        Self { connection }
    }
}

#[derive(Debug)]
pub enum BleConnectorError {
    Unknown,
}

impl Error for BleConnectorError {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::Other
    }
}

impl<'a, T> Io for BleConnector<'a, T>
where
    T: Read + Write,
{
    type Error = BleConnectorError;
}

impl<'a, T> Read for BleConnector<'a, T>
where
    T: Read + Write,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        match self.connection.read(buf) {
            Ok(len) => Ok(len),
            Err(_) => Err(BleConnectorError::Unknown),
        }
    }
}

impl<'a, T> Write for BleConnector<'a, T>
where
    T: Read + Write,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        match self.connection.write(buf) {
            Ok(len) => Ok(len),
            Err(_) => Err(BleConnectorError::Unknown),
        }
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        match self.connection.flush() {
            Ok(v) => Ok(v),
            Err(_) => Err(BleConnectorError::Unknown),
        }
    }
}
