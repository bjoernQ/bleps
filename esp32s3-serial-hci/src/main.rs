// Flash this to an ESP32-S3 and use it together with the "example"

#![no_std]
#![no_main]

use embedded_io_blocking::{Read, Write};
use esp32s3_hal::{
    clock::{ClockControl, CpuClock},
    peripherals::Peripherals,
    prelude::*,
    timer::TimerGroup,
    Rng, Uart,
};
use esp_backtrace as _;
use esp_println::logger::init_logger;
use esp_wifi::ble::controller::BleConnector;

const CNT: usize = 5000;

#[entry]
fn main() -> ! {
    init_logger(log::LevelFilter::Off);

    let peripherals = Peripherals::take();
    let system = peripherals.SYSTEM.split();
    let clocks = ClockControl::configure(system.clock_control, CpuClock::Clock240MHz).freeze();

    let timer_group1 = TimerGroup::new(peripherals.TIMG1, &clocks);

    let init = esp_wifi::initialize(
        esp_wifi::EspWifiInitFor::Ble,
        timer_group1.timer0,
        Rng::new(peripherals.RNG),
        system.radio_clock_control,
        &clocks,
    )
    .unwrap();

    let mut connector = BleConnector::new(&init, peripherals.BT);

    let mut serial = Uart::new(peripherals.UART0, &clocks);

    esp32s3_hal::prelude::_embedded_hal_serial_Write::write(&mut serial, 0xff).unwrap();

    let mut buffer = [0u8; 256];
    loop {
        let mut cnt = CNT;
        loop {
            let b = esp32s3_hal::prelude::_embedded_hal_serial_Read::read(&mut serial);
            match b {
                Ok(b) => {
                    connector.write(&[b]).unwrap();
                    cnt = CNT;
                }
                Err(_) => {
                    cnt -= 1;

                    if cnt == 0 {
                        break;
                    }
                }
            }
        }

        let mut cnt = CNT;
        loop {
            match connector.read(&mut buffer) {
                Ok(len) => {
                    if len == 0 {
                        cnt -= 1;

                        if cnt == 0 {
                            break;
                        }
                    } else {
                        cnt = CNT;
                        serial.write_bytes(&buffer[..len]).unwrap();
                    }
                }
                Err(_) => {
                    cnt -= 1;

                    if cnt == 0 {
                        break;
                    }
                }
            }
        }
    }
}
