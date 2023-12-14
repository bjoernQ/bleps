// Use with the esp32s3-serial-hci

use std::{
    process::exit,
    sync::{Arc, Mutex},
    time::Duration,
};

use bleps::{
    ad_structure::{
        create_advertising_data, AdStructure, BR_EDR_NOT_SUPPORTED, LE_GENERAL_DISCOVERABLE,
    },
    attribute_server::{AttributeServer, NotificationData, WorkResult},
    gatt, Addr, Ble, HciConnector,
};
use embedded_io_adapters::std::FromStd;
use embedded_io_blocking::{Error, ErrorType, Read, Write};
use rand_core::OsRng;

fn main() {
    env_logger::init();

    if std::env::args().len() != 2 {
        println!("Provide the serial port as the one and only command line argument.");
        return;
    }

    let args: Vec<String> = std::env::args().collect();

    let port = serialport::new(&args[1], 115_200)
        .timeout(Duration::from_millis(300))
        .open()
        .expect("Failed to open port");

    println!("Reset the target");

    let mut serial = FromStd::new(port);

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
    println!("Q to exit, N to notify, X force disconnect");

    crossterm::terminal::enable_raw_mode().unwrap();

    let mut ltk = None;

    loop {
        let connector = BleConnector::new(&mut serial);
        let hci = HciConnector::new(connector, current_millis);
        let mut ble = Ble::new(&hci);

        println!("{:?}", ble.init());

        let local_addr = Addr::from_le_bytes(false, ble.cmd_read_br_addr().unwrap());

        println!("{:?}", ble.cmd_set_le_advertising_parameters());
        println!(
            "{:?}",
            ble.cmd_set_le_advertising_data(
                create_advertising_data(&[
                    AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
                    AdStructure::ServiceUuids16(&[Uuid::Uuid16(0x1809)]),
                    AdStructure::CompleteLocalName("BLEPS"),
                ])
                .unwrap()
            )
        );
        println!("{:?}", ble.cmd_set_le_advertise_enable(true));

        println!("started advertising");

        let val = Arc::new(Mutex::new(Vec::from(
            &b"Hello BLE! Hello BLE! 01234567890123456789 ABCDEFG abcdefg"[..],
        )));

        let mut rf = {
            let val = val.clone();
            move |offset: usize, data: &mut [u8]| {
                let val = val.lock().unwrap();
                let off = offset as usize;
                if off < val.len() {
                    let len = data.len().min(val.len() - off);
                    data[..len].copy_from_slice(&val[off..off + len]);
                    println!("SEND: Offset {}, data {:x?}", offset, &data[..len]);
                    len
                } else {
                    0
                }
            }
        };
        let mut wf = {
            let val = val.clone();
            move |offset: usize, data: &[u8]| {
                println!("RECEIVED: Offset {}, data {:x?}", offset, data);
                let mut val = val.lock().unwrap();
                let off = offset as usize;
                if off < val.len() {
                    let len = val.len() - off;
                    let olen = data.len().min(len);
                    val[off..off + olen].copy_from_slice(&data[..olen]);
                    if data.len() > len {
                        val.extend_from_slice(&data[olen..]);
                    }
                }
            }
        };

        let mut wf2 = |offset: usize, data: &[u8]| {
            println!("RECEIVED2: Offset {}, data {:x?}", offset, data);
        };

        let mut rf3 = |_offset: usize, data: &mut [u8]| {
            data[..5].copy_from_slice(&b"Hola!"[..]);
            5
        };
        let mut wf3 = |offset: usize, data: &[u8]| {
            println!("RECEIVED3: Offset {}, data {:x?}", offset, data);
        };

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
                characteristic {
                    name: "my_characteristic",
                    uuid: "987312e0-2354-11eb-9f10-fbc30a62cf38",
                    notify: true,
                    read: rf3,
                    write: wf3,
                },
            ],
        },]);

        let mut rng = OsRng::default();
        let mut srv = AttributeServer::new_with_ltk(
            &mut ble,
            &mut gatt_attributes,
            local_addr,
            ltk,
            &mut rng,
        );

        let mut pin_callback = |pin: u32| {
            println!("PIN is {pin}");
        };

        srv.set_pin_callback(Some(&mut pin_callback));

        let mut response = [b'H', b'e', b'l', b'l', b'o', b'0'];

        loop {
            let mut notification = None;

            if let Ok(true) = crossterm::event::poll(Duration::from_micros(1)) {
                let event = crossterm::event::read().unwrap();
                match event {
                    crossterm::event::Event::Key(key_event) => match key_event.code {
                        crossterm::event::KeyCode::Char('c')
                            if key_event.modifiers == crossterm::event::KeyModifiers::CONTROL =>
                        {
                            exit(0);
                        }
                        crossterm::event::KeyCode::Char('q') => {
                            exit(0);
                        }
                        crossterm::event::KeyCode::Char('n') => {
                            println!("notify if enabled");
                            let mut cccd = [0u8; 1];
                            if let Some(1) = srv.get_characteristic_value(
                                my_characteristic_notify_enable_handle,
                                0,
                                &mut cccd,
                            ) {
                                // if notifications enabled
                                if cccd[0] == 1 {
                                    response[5] = b'0' + ((response[5] + 1) % 10);
                                    notification = Some(NotificationData::new(
                                        my_characteristic_handle,
                                        &response[..],
                                    ));
                                }
                            }
                        }
                        crossterm::event::KeyCode::Char('x') => {
                            srv.disconnect(0x13).unwrap();
                        }
                        _ => (),
                    },
                    _ => (),
                }
            }

            match srv.do_work_with_notification(notification) {
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

        ltk = srv.get_ltk();
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
    fn kind(&self) -> embedded_io_blocking::ErrorKind {
        embedded_io_blocking::ErrorKind::Other
    }
}

impl<'a, T> ErrorType for BleConnector<'a, T>
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
