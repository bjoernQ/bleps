#![feature(assert_matches)]

use std::{assert_matches::assert_matches, cell::RefCell};

extern crate std;

use bleps::ad_structure::AdvertisementDataError;
use bleps::{
    acl::{AclPacket, BoundaryFlag, ControllerBroadcastFlag, HostBroadcastFlag},
    ad_structure::{
        create_advertising_data, AdStructure, BR_EDR_NOT_SUPPORTED, LE_GENERAL_DISCOVERABLE,
    },
    att::{Att, AttErrorCode, Uuid, ATT_READ_BY_GROUP_TYPE_REQUEST_OPCODE},
    attribute::Attribute,
    attribute_server::{AttributeServer, CHARACTERISTIC_UUID16, PRIMARY_SERVICE_UUID16},
    command::{Command, CommandHeader},
    event::{ErrorCode, EventType},
    l2cap::L2capPacket,
    Ble, Data, HciConnection, PollResult,
};
use p256::elliptic_curve::rand_core::OsRng;

struct TestConnector {
    to_read: RefCell<[u8; 128]>,
    to_write: RefCell<[u8; 128]>,
    read_idx: RefCell<usize>,
    read_max: RefCell<usize>,
    write_idx: RefCell<usize>,
    current_millis: RefCell<[u64; 128]>,
    current_millis_idx: RefCell<usize>,
}

impl TestConnector {
    fn reset(&self) {
        *(self.read_idx.borrow_mut()) = 0;
        *(self.read_max.borrow_mut()) = 0;
        *(self.write_idx.borrow_mut()) = 0;
    }

    fn provide_data_to_read(&self, data: &[u8]) {
        let len = data.len();
        let from = *(self.read_max.borrow());
        let to = from + len;
        (self.to_read.borrow_mut())[from..to].copy_from_slice(data);
        *(self.read_max.borrow_mut()) += len;
    }

    fn set_read_max(&self, v: usize) {
        *(self.read_max.borrow_mut()) = v;
    }

    fn set_read_idx(&self, v: usize) {
        *(self.read_idx.borrow_mut()) = v;
    }

    fn _set_write_idx(&self, v: usize) {
        *(self.write_idx.borrow_mut()) = v;
    }

    fn _get_read_max(&self) -> usize {
        *(self.read_max.borrow())
    }

    fn _get_read_idx(&self) -> usize {
        *(self.read_idx.borrow())
    }

    fn get_write_idx(&self) -> usize {
        *(self.write_idx.borrow())
    }

    fn get_to_write_at(&self, idx: usize) -> u8 {
        (self.to_write.borrow())[idx]
    }

    fn set_current_millis_at(&self, idx: usize, v: u64) {
        (self.current_millis.borrow_mut())[idx] = v;
    }

    fn get_current_millis_idx(&self) -> usize {
        *(self.current_millis_idx.borrow())
    }

    fn get_written_data(&self) -> Data {
        Data::new(&(self.to_write.borrow_mut())[..*(self.write_idx.borrow())])
    }
}

impl HciConnection for TestConnector {
    fn read(&self) -> Option<u8> {
        if self.read_max > self.read_idx {
            let r = (self.to_read.borrow())[*(self.read_idx.borrow())];
            *(self.read_idx.borrow_mut()) += 1;
            Some(r)
        } else {
            None
        }
    }

    fn write(&self, data: u8) {
        (self.to_write.borrow_mut())[*(self.write_idx.borrow())] = data;
        *(self.write_idx.borrow_mut()) += 1;
    }

    fn millis(&self) -> u64 {
        let r = (self.current_millis.borrow())[*(self.current_millis_idx.borrow())];
        *(self.current_millis_idx.borrow_mut()) += 1;
        r
    }
}

fn connector() -> TestConnector {
    TestConnector {
        to_read: RefCell::new([0u8; 128]),
        to_write: RefCell::new([0u8; 128]),
        read_idx: RefCell::new(0),
        read_max: RefCell::new(0),
        write_idx: RefCell::new(0),
        current_millis: RefCell::new([0; 128]),
        current_millis_idx: RefCell::new(0),
    }
}

#[test]
fn testing_will_work() {
    let connector = connector();

    connector.set_read_max(1);
    assert_eq!(Some(0), connector.read());
    assert_eq!(None, connector.read());

    connector.set_read_idx(0);

    assert_eq!(Some(0), connector.read());
    assert_eq!(None, connector.read());

    connector.write(0xff);

    assert_eq!(connector.get_write_idx(), 1);
    assert_eq!(connector.get_to_write_at(0), 0xff);
}

#[test]
fn parse_event() {
    let connector = connector();
    let mut ble = Ble::new(&connector);

    connector.provide_data_to_read(&[0x04, 0x0e, 0x04, 0x05, 0x03, 0x0c, 0x00]);

    let res = ble.poll();

    assert_matches!(res, Some(PollResult::Event(EventType::CommandComplete { num_packets: 5, opcode: 0x0c03, data})) if data.as_slice() == &[0] );

    connector.reset();
}

#[test]
fn init_works() {
    let connector = connector();
    let mut ble = Ble::new(&connector);

    connector.provide_data_to_read(&[
        0x04, 0x0e, 0x04, 0x05, 0x03, 0x0c, 0x00, 0x04, 0x0e, 0x04, 0x05, 0x01, 0x0c, 0x00,
    ]);

    let res = ble.init();

    assert_matches!(res, Ok(()));

    assert_eq!(connector.get_write_idx(), 16);
    assert_eq!(connector.get_to_write_at(0), 0x01);
    assert_eq!(connector.get_to_write_at(1), 0x03);
    assert_eq!(connector.get_to_write_at(2), 0x0c);
    assert_eq!(connector.get_to_write_at(3), 0x00);

    assert_eq!(connector.get_to_write_at(4), 0x01);
    assert_eq!(connector.get_to_write_at(5), 0x01);
    assert_eq!(connector.get_to_write_at(6), 0x0c);
    assert_eq!(connector.get_to_write_at(7), 0x08);
    assert_eq!(connector.get_to_write_at(8), 0xff);
    assert_eq!(connector.get_to_write_at(9), 0xff);
    assert_eq!(connector.get_to_write_at(10), 0xff);
    assert_eq!(connector.get_to_write_at(11), 0xff);
    assert_eq!(connector.get_to_write_at(12), 0xff);
    assert_eq!(connector.get_to_write_at(13), 0xff);
    assert_eq!(connector.get_to_write_at(14), 0xff);
    assert_eq!(connector.get_to_write_at(15), 0xff);
}

#[test]
fn init_fails_timeout() {
    let connector = connector();
    let mut ble = Ble::new(&connector);

    connector.set_current_millis_at(0, 0);
    connector.set_current_millis_at(1, 100);
    connector.set_current_millis_at(2, 2000);

    let res = ble.init();

    assert_matches!(res, Err(bleps::Error::Timeout));
    assert_eq!(connector.get_current_millis_idx(), 3);
}

#[test]
fn init_fails() {
    let connector = connector();
    let mut ble = Ble::new(&connector);

    connector.provide_data_to_read(&[0x04, 0x0e, 0x04, 0x05, 0x03, 0x0c, 0xff]);

    let res = ble.init();

    assert_matches!(res, Err(bleps::Error::Failed(255)));

    assert_eq!(connector.get_write_idx(), 4);
    assert_eq!(connector.get_to_write_at(0), 0x01);
    assert_eq!(connector.get_to_write_at(1), 0x03);
    assert_eq!(connector.get_to_write_at(2), 0x0c);
    assert_eq!(connector.get_to_write_at(3), 0x00);
}

#[test]
pub fn command_header_reset_parse_works() {
    let header = CommandHeader::from_bytes(&[0x03, 0x0c, 0x00]);

    assert_eq!(header.ogf(), 0x03);
    assert_eq!(header.ocf(), 0x03);
    assert_eq!(header.len, 0x00);
}

#[test]
pub fn command_header_let_set_adv_param_parse_works() {
    let header = CommandHeader::from_bytes(&[0x06, 0x20, 0x0f]);

    assert_eq!(header.ogf(), 0x08);
    assert_eq!(header.ocf(), 0x06);
    assert_eq!(header.len, 0x0f);
}

#[test]
pub fn command_header_reset_works() {
    let header = CommandHeader::from_ogf_ocf(0x03, 0x03, 0x00);

    assert_eq!(header.ogf(), 0x03);
    assert_eq!(header.ocf(), 0x03);
    assert_eq!(header.opcode, 0x0c03);
    assert_eq!(header.len, 0x00);
}

#[test]
pub fn command_header_set_adv_param_works() {
    let header = CommandHeader::from_ogf_ocf(0x08, 0x06, 0x0f);

    assert_eq!(header.ogf(), 0x08);
    assert_eq!(header.ocf(), 0x06);
    assert_eq!(header.opcode, 0x2006);
    assert_eq!(header.len, 0x0f);
}

#[test]
fn create_reset_command_works() {
    let data = Command::Reset.encode();
    assert_eq!(data.len, 4);
    assert_eq!(data.data[0..4], [0x01, 0x03, 0x0c, 0x00]);
}

#[test]
fn create_le_set_advertising_parameters_works() {
    let data = Command::LeSetAdvertisingParameters.encode();
    assert_eq!(data.len, 19);
    assert_eq!(
        data.data[..19],
        [0x01, 0x06, 0x20, 0x0f, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0]
    );
}

#[test]
fn set_advertising_parameters_works() {
    let connector = connector();
    let mut ble = Ble::new(&connector);

    connector.provide_data_to_read(&[0x04, 0x0e, 0x04, 0x05, 0x06, 0x20, 0x00]);

    let res = ble.cmd_set_le_advertising_parameters();

    assert_matches!(res, Ok(EventType::CommandComplete{ num_packets: 5, opcode: 0x2006, data}) if data.as_slice() == &[0]);
}

#[test]
fn create_le_set_advertising_data_works() {
    let data = Command::LeSetAdvertisingData {
        data: Data::new(&[1, 2, 3, 4, 5]),
    }
    .encode();
    assert_eq!(data.len, 9);
    assert_eq!(data.data[..9], [0x01, 0x08, 0x20, 0x05, 1, 2, 3, 4, 5]);
}

#[test]
fn le_set_advertising_data_works() {
    let connector = connector();
    let mut ble = Ble::new(&connector);

    connector.provide_data_to_read(&[0x04, 0x0e, 0x04, 0x05, 0x08, 0x20, 0x00]);

    let res = ble.cmd_set_le_advertising_data(Data::new(&[1, 2, 3, 4, 5]));

    assert_matches!(res, Ok(EventType::CommandComplete{ num_packets: 5, opcode: 0x2008, data}) if data.as_slice() == &[0]);
}

#[test]
fn create_le_set_advertise_enable_works() {
    let data = Command::LeSetAdvertiseEnable(true).encode();
    assert_eq!(data.len, 5);
    assert_eq!(data.data[..5], [0x01, 0x0a, 0x20, 0x01, 0x01]);
}

#[test]
fn le_set_advertise_enable_works() {
    let connector = connector();
    let mut ble = Ble::new(&connector);

    connector.provide_data_to_read(&[0x04, 0x0e, 0x04, 0x05, 0x0a, 0x20, 0x00]);

    let res = ble.cmd_set_le_advertise_enable(false);

    assert_matches!(res, Ok(EventType::CommandComplete{ num_packets: 5, opcode: 0x200a, data}) if data.as_slice() == &[0]);
}

#[test]
fn receiving_async_data_works() {
    let connector = connector();
    let mut ble = Ble::new(&connector);

    connector.provide_data_to_read(&[
        0x02, 0x00, 0x20, 0x0b, 0x00, 0x07, 0x00, 0x04, 0x00, 0x10, 0x01, 0x00, 0xff, 0xff, 0x00,
        0x28,
    ]);

    let res = ble.poll();

    assert_matches!(res,
        Some(PollResult::AsyncData(AclPacket {
            handle: 0,
            boundary_flag: BoundaryFlag::FirstAutoFlushable,
            bc_flag: ControllerBroadcastFlag::PointToPoint,
            data,
        })) if data.as_slice() == &[0x7, 0x0, 0x4, 0x0, 0x10, 0x1, 0x0, 0xff, 0xff, 0x0, 0x28]
    );
}

#[test]
fn receiving_disconnection_complete_works() {
    let connector = connector();
    let mut ble = Ble::new(&connector);

    connector.provide_data_to_read(&[0x04, 0x05, 0x04, 0x00, 0x00, 0x00, 0x13]);

    let res = ble.poll();

    assert_matches!(
        res,
        Some(PollResult::Event(EventType::DisconnectComplete {
            handle: 0,
            status: ErrorCode::Okay,
            reason: ErrorCode::RemoteUserTerminatedConnection
        }))
    );
}

#[test]
fn receiving_number_of_completed_packets_works() {
    let connector = connector();
    let mut ble = Ble::new(&connector);

    connector.provide_data_to_read(&[0x04, 0x13, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00]);

    let res = ble.poll();

    assert_matches!(
        res,
        Some(PollResult::Event(EventType::NumberOfCompletedPackets {
            number_of_connection_handles: 1,
            connection_handles: 0,
            completed_packets: 1,
        }))
    );
}

#[test]
fn receiving_read_by_group_type_works() {
    let connector = connector();
    let mut ble = Ble::new(&connector);

    connector.provide_data_to_read(&[
        0x02, 0x00, 0x20, 0x0b, 0x00, 0x07, 0x00, 0x04, 0x00, 0x10, 0x01, 0x00, 0xff, 0xff, 0x00,
        0x28,
    ]);

    let res = ble.poll();
    match res {
        Some(res) => match res {
            PollResult::Event(_) => assert!(true, "Expected async data"),
            PollResult::AsyncData(res) => {
                let res = Att::decode(L2capPacket::decode(res).unwrap().1);
                assert_matches!(
                    res,
                    Ok(Att::ReadByGroupTypeReq {
                        start: 0x0001,
                        end: 0xffff,
                        group_type: Uuid::Uuid16(0x2800),
                    })
                )
            }
        },
        None => assert!(true, "Expected result"),
    }
}

#[test]
fn create_read_by_group_type_resp_works() {
    let mut res = Data::new_att_read_by_group_type_response();
    res.append_att_read_by_group_type_response(0x0001, 0x0010, &Uuid::Uuid16(0x1801));
    res.append_att_read_by_group_type_response(0x0020, 0x0030, &Uuid::Uuid16(0x1802));

    assert_matches!(
        res.as_slice(),
        [0x11, 0x06, 0x01, 0x00, 0x10, 0x00, 0x01, 0x18, 0x20, 0x00, 0x30, 0x00, 0x02, 0x18]
    );
}

#[test]
fn create_read_by_group_type_resp_acl_works() {
    let mut res = Data::new_att_read_by_group_type_response();
    res.append_att_read_by_group_type_response(0x0001, 0x0010, &Uuid::Uuid16(0x1801));
    res.append_att_read_by_group_type_response(0x0020, 0x0030, &Uuid::Uuid16(0x1802));
    let res = L2capPacket::encode(res);
    let res = AclPacket::encode(
        0x0000,
        BoundaryFlag::FirstAutoFlushable,
        HostBroadcastFlag::NoBroadcast,
        res,
    );

    assert_matches!(
        res.as_slice(),
        &[
            0x02, 0x00, 0x20, 0x12, 0x00, 0x0e, 0x00, 0x04, 0x00, 0x11, 0x06, 0x01, 0x00, 0x10,
            0x00, 0x01, 0x18, 0x20, 0x00, 0x30, 0x00, 0x02, 0x18,
        ]
    );
}

#[test]
fn create_error_resp_works() {
    let res = Data::new_att_error_response(
        ATT_READ_BY_GROUP_TYPE_REQUEST_OPCODE,
        0x1234,
        AttErrorCode::AttributeNotFound,
    );

    assert_matches!(res.as_slice(), &[0x01, 0x10, 0x34, 0x12, 0x0a,]);
}

#[test]
fn receiving_read_by_type_works() {
    let connector = connector();
    let mut ble = Ble::new(&connector);

    connector.provide_data_to_read(&[
        0x02, 0x00, 0x20, 0x0b, 0x00, 0x07, 0x00, 0x04, 0x00, 0x08, 0x01, 0x00, 0x02, 0x00, 0x02,
        0x28,
    ]);

    let res = ble.poll();
    match res {
        Some(res) => match res {
            PollResult::Event(_) => assert!(true, "Expected async data"),
            PollResult::AsyncData(res) => {
                let res = Att::decode(L2capPacket::decode(res).unwrap().1);
                assert_matches!(
                    res,
                    Ok(Att::ReadByTypeReq {
                        start: 0x0001,
                        end: 0x0002,
                        attribute_type: Uuid::Uuid16(0x2802),
                    })
                )
            }
        },
        None => assert!(true, "Expected result"),
    }
}

#[test]
fn create_read_by_type_resp_works() {
    let mut res = Data::new_att_read_by_type_response();
    res.append_value(0x0002u16);
    res.append(&[1u8, 2u8, 3u8, 4u8]);
    res.append_att_read_by_type_response();

    assert_matches!(
        res.as_slice(),
        [0x09, 0x06, 0x02, 0x00, 0x01, 0x02, 0x03, 0x04]
    );
}

// TODO test EXCHANGE_MTU

// TODO test FIND_TYPE_VALUE

#[test]
fn receiving_read_works() {
    let connector = connector();
    let mut ble = Ble::new(&connector);

    connector.provide_data_to_read(&[
        0x02, 0x00, 0x20, 0x07, 0x00, 0x03, 0x00, 0x04, 0x00, 0x0a, 0x03, 0x00,
    ]);

    let res = ble.poll();
    match res {
        Some(res) => match res {
            PollResult::Event(_) => assert!(true, "Expected async data"),
            PollResult::AsyncData(res) => {
                let res = Att::decode(L2capPacket::decode(res).unwrap().1);
                assert_matches!(res, Ok(Att::ReadReq { handle: 0x03 }))
            }
        },
        None => assert!(true, "Expected result"),
    }
}

#[test]
fn create_read_resp_works() {
    let mut res = Data::new_att_read_response();
    res.append(&[0x01, 0x02, 0x03, 0x04]);

    assert_matches!(res.as_slice(), &[0x0b, 0x01, 0x02, 0x03, 0x04,]);
}

#[test]
fn receiving_write_works() {
    let connector = connector();
    let mut ble = Ble::new(&connector);

    connector.provide_data_to_read(&[
        0x02, 0x00, 0x20, 0x08, 0x00, 0x04, 0x00, 0x04, 0x00, 0x12, 0x03, 0x00, 0x0ff,
    ]);

    let res = ble.poll();
    match res {
        Some(res) => match res {
            PollResult::Event(_) => assert!(true, "Expected async data"),
            PollResult::AsyncData(res) => {
                let res = Att::decode(L2capPacket::decode(res).unwrap().1);
                assert_matches!(
                    res,
                    Ok(Att::WriteReq {
                        handle: 0x03,
                        data
                    }) if data.as_slice() == &[0xff]
                )
            }
        },
        None => assert!(true, "Expected result"),
    }
}

#[test]
fn create_write_resp_works() {
    let res = Data::new_att_write_response();

    assert_matches!(res.as_slice(), &[0x13]);
}

#[test]
fn create_advertising_data_works() {
    let res = create_advertising_data(&[
        AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
        AdStructure::ServiceUuids16(&[Uuid::Uuid16(0x1809)]),
        AdStructure::CompleteLocalName("Ble-Example!"),
    ])
    .unwrap();

    println!("{:x?}", res);

    assert_matches!(
        res.as_slice(),
        &[
            21, 2, 1, 6, 3, 2, 9, 24, 13, 9, 66, 108, 101, 45, 69, 120, 97, 109, 112, 108, 101, 33,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]
    );
}

#[test]
fn create_advertising_data_fails() {
    let res = create_advertising_data(&[
        AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
        AdStructure::ServiceUuids16(&[Uuid::Uuid16(0x1809)]),
        AdStructure::CompleteLocalName(
            "Ble-Example!Ble-Example!Ble-Example!Ble-Example!Ble-Example!Ble-Example!Ble-Example!",
        ),
    ]);

    assert_matches!(res, Err(AdvertisementDataError::TooLong));
}

#[test]
fn attribute_server_discover_two_services() {
    let connector = connector();
    let mut ble = Ble::new(&connector);

    let mut rf1 = |_offset: usize, data: &mut [u8]| -> usize {
        data[0] = 0;
        1
    };
    let mut wf1 = |_offset: usize, _data: &[u8]| {};

    let mut rf2 = |_offset: usize, data: &mut [u8]| -> usize {
        data[0] = 0;
        1
    };
    let mut wf2 = |_offset: usize, _data: &[u8]| {};

    let srv_uuid: [u8; 16] = [
        0xC9, 0x15, 0x15, 0x96, 0x54, 0x56, 0x64, 0xB3, 0x38, 0x45, 0x26, 0x5D, 0xF1, 0x62, 0x6A,
        0xA8,
    ];
    let mut srv_uuid_att_data = &srv_uuid[..];
    let primaray_srv = Attribute::new(PRIMARY_SERVICE_UUID16, &mut srv_uuid_att_data);

    let char_data = [
        0x02, // 1 byte properties: READ = 0x02
        0x03, 0x00, // 2 bytes handle = 0x0007
        0xC9, 0x15, 0x15, 0x96, 0x54, 0x56, 0x64, 0xB3, 0x38, 0x45, 0x26, 0x5D, 0xF1, 0x62, 0x6A,
        0xA8, // 128 bit UUID like above
    ];
    let mut char_att_data = &char_data;
    let char = Attribute::new(CHARACTERISTIC_UUID16, &mut char_att_data);

    let mut custom_char_att_data = (&mut rf1, &mut wf1);
    let custom_char_att_data_attr = Attribute::new(
        Uuid::Uuid128([
            0xC9, 0x15, 0x15, 0x96, 0x54, 0x56, 0x64, 0xB3, 0x38, 0x45, 0x26, 0x5D, 0xF1, 0x62,
            0x6A, 0xA8,
        ]),
        &mut custom_char_att_data,
    );

    let srv_uuid2: [u8; 16] = [
        0xC8, 0x15, 0x15, 0x96, 0x54, 0x56, 0x64, 0xB3, 0x38, 0x45, 0x26, 0x5D, 0xF1, 0x62, 0x6A,
        0xA8,
    ];
    let mut srv_uuid_att_data2 = &srv_uuid2[..];
    let primaray_srv2 = Attribute::new(PRIMARY_SERVICE_UUID16, &mut srv_uuid_att_data2);

    let char_data2 = [
        0x02 | 0x08, // 1 byte properties: READ = 0x02, WRITE WITH RESPONSE = 0x08
        0x06,
        0x00, // 2 bytes handle = 0x0007
        0xC8,
        0x15,
        0x15,
        0x96,
        0x54,
        0x56,
        0x64,
        0xB3,
        0x38,
        0x45,
        0x26,
        0x5D,
        0xF1,
        0x62,
        0x6A,
        0xA8, // 128 bit UUID like above
    ];
    let mut char_att_data2 = &char_data2;
    let char2 = Attribute::new(CHARACTERISTIC_UUID16, &mut char_att_data2);

    let mut custom_char_att_data2 = (&mut rf2, &mut wf2);
    let custom_char_att_data_attr2 = Attribute::new(
        Uuid::Uuid128([
            0xC9, 0x15, 0x15, 0x96, 0x54, 0x56, 0x64, 0xB3, 0x38, 0x45, 0x26, 0x5D, 0xF1, 0x62,
            0x6A, 0xA8,
        ]),
        &mut custom_char_att_data2,
    );

    let mut val_att_data = &(32u32,);
    let val = Attribute::new(CHARACTERISTIC_UUID16, &mut val_att_data);

    let attributes = &mut [
        primaray_srv,
        char,
        custom_char_att_data_attr,
        primaray_srv2,
        char2,
        custom_char_att_data_attr2,
        val,
    ];

    let mut rng = OsRng::default();
    let mut srv = AttributeServer::new(&mut ble, attributes, &mut rng);

    // ReadByGroupTypeReq { start: 1, end: ffff, group_type: Uuid16(2800) }
    connector.provide_data_to_read(&[
        0x02, 0x00, 0x20, 0x0b, 0x00, 0x07, 0x00, 0x04, 0x00, 0x10, 0x01, 0x00, 0xff, 0xff, 0x00,
        0x28,
    ]);
    assert_matches!(srv.do_work(), Ok(_));
    // check response (1-3, 0x2800)
    let response_data = connector.get_written_data();
    assert_eq!(
        response_data.as_slice(),
        &[
            0x02, 0x00, 0x20, 0x1A, 0x00, 0x16, 0x00, 0x04, 0x00, 0x11, 0x14, 0x01, 0x00, 0x03,
            0x00, 0xC9, 0x15, 0x15, 0x96, 0x54, 0x56, 0x64, 0xB3, 0x38, 0x45, 0x26, 0x5D, 0xF1,
            0x62, 0x6A, 0xA8,
        ]
    );

    // ReadByGroupTypeReq { start: 4, end: ffff, group_type: Uuid16(2800) }
    connector.reset();
    connector.provide_data_to_read(&[
        0x02, 0x00, 0x20, 0x0b, 0x00, 0x07, 0x00, 0x04, 0x00, 0x10, 0x04, 0x00, 0xff, 0xff, 0x00,
        0x28,
    ]);
    assert_matches!(srv.do_work(), Ok(_));
    // check response (4-6, 0x2800)
    let response_data = connector.get_written_data();
    assert_eq!(
        response_data.as_slice(),
        &[
            0x02, 0x00, 0x20, 0x1a, 0x00, 0x16, 0x00, 0x04, 0x00, 0x11, 0x14, 0x04, 0x00, 0x07,
            0x00, 0xC8, 0x15, 0x15, 0x96, 0x54, 0x56, 0x64, 0xB3, 0x38, 0x45, 0x26, 0x5D, 0xF1,
            0x62, 0x6A, 0xA8,
        ]
    );

    // ReadByGroupTypeReq { start: 7, end: ffff, group_type: Uuid16(2800) }
    connector.reset();
    connector.provide_data_to_read(&[
        0x02, 0x00, 0x20, 0x0b, 0x00, 0x07, 0x00, 0x04, 0x00, 0x10, 0x07, 0x00, 0xff, 0xff, 0x00,
        0x28,
    ]);
    assert_matches!(srv.do_work(), Ok(_));
    // check response (not found)
    let response_data = connector.get_written_data();
    assert_eq!(
        response_data.as_slice(),
        &[0x02, 0x00, 0x20, 0x09, 0x00, 0x05, 0x00, 0x04, 0x00, 0x01, 0x10, 0x07, 0x00, 0x0a]
    );
}
