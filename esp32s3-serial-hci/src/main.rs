// Flash this to an ESP32-S3 and use it together with the "example"

#![no_std]
#![no_main]

use embedded_io::blocking::{Read, Write};
use esp32s3_hal::{
    clock::{ClockControl, CpuClock},
    peripherals::Peripherals,
    prelude::*,
    timer::TimerGroup,
    Rng, Rtc, Uart,
};
use esp_backtrace as _;
use esp_println::logger::init_logger;
use esp_wifi::ble::controller::BleConnector;

const CNT: usize = 5000;

#[entry]
fn main() -> ! {
    init_logger(log::LevelFilter::Off);

    let peripherals = Peripherals::take();
    let mut system = peripherals.SYSTEM.split();
    let clocks = ClockControl::configure(system.clock_control, CpuClock::Clock240MHz).freeze();

    // Disable the RTC and TIMG watchdog timers
    let mut rtc = Rtc::new(peripherals.RTC_CNTL);
    let timer_group0 = TimerGroup::new(
        peripherals.TIMG0,
        &clocks,
        &mut system.peripheral_clock_control,
    );
    let mut wdt0 = timer_group0.wdt;
    let timer_group1 = TimerGroup::new(
        peripherals.TIMG1,
        &clocks,
        &mut system.peripheral_clock_control,
    );
    let mut wdt1 = timer_group1.wdt;

    rtc.rwdt.disable();
    wdt0.disable();
    wdt1.disable();

    let bt = peripherals.RADIO.split().1;
    esp_wifi::initialize(
        timer_group1.timer0,
        Rng::new(peripherals.RNG),
        system.radio_clock_control,
        &clocks,
    )
    .unwrap();

    let mut connector = BleConnector::new(bt);

    let mut serial = Uart::new(peripherals.UART0, &mut system.peripheral_clock_control);

    serial.write(0xff).unwrap();

    let mut buffer = [0u8; 256];
    loop {
        let mut cnt = CNT;
        loop {
            let b = serial.read();
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
