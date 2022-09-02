use log::info;

use crate::{
    acl::{encode_acl_packet, BoundaryFlag, HostBroadcastFlag},
    att::{
        att_encode_error_response, att_encode_exchange_mtu_response,
        att_encode_read_by_group_type_response, att_encode_read_by_type_response,
        att_encode_read_response, att_encode_write_response, parse_att, Att, AttErrorCode,
        AttParseError, AttributeData, AttributePayloadData, Uuid,
        ATT_FIND_BY_TYPE_VALUE_REQUEST_OPCODE, ATT_READ_BY_GROUP_TYPE_REQUEST_OPCODE,
        ATT_READ_BY_TYPE_REQUEST_OPCODE,
    },
    event::EventType,
    l2cap::{encode_l2cap, parse_l2cap, L2capParseError},
    Ble, Data,
};

const PRIMARY_SERVICE_UUID16: Uuid = Uuid::Uuid16(0x2800);
const CHARACTERISTIC_UUID16: Uuid = Uuid::Uuid16(0x2803);

#[derive(Debug)]
pub enum WorkResult {
    DidWork,
    GotDisconnected,
}

#[derive(Debug)]
pub enum AttributeServerError {
    L2capError(L2capParseError),
    AttError(AttParseError),
}

impl From<L2capParseError> for AttributeServerError {
    fn from(err: L2capParseError) -> Self {
        AttributeServerError::L2capError(err)
    }
}

impl From<AttParseError> for AttributeServerError {
    fn from(err: AttParseError) -> Self {
        AttributeServerError::AttError(err)
    }
}

pub struct AttributeServer<'a> {
    ble: &'a mut Ble<'a>,
    services: &'a mut [Service<'a>],
}

impl<'a> AttributeServer<'a> {
    pub fn new(ble: &'a mut Ble<'a>, services: &'a mut [Service<'a>]) -> AttributeServer<'a> {
        let mut current_handle = 1;
        for service in services.iter_mut() {
            service.start_handle = current_handle;
            service.end_handle = current_handle + 2;
            service.characteristics_handle = current_handle + 2;
            current_handle += 3;
        }
        AttributeServer { ble, services }
    }

    pub fn do_work(&mut self) -> Result<WorkResult, AttributeServerError> {
        let packet = self.ble.poll();

        if packet.is_some() {
            info!("polled: {:?}", packet);
        }

        match packet {
            None => Ok(WorkResult::DidWork),
            Some(packet) => match packet {
                crate::PollResult::Event(evt) => {
                    if let EventType::DisconnectComplete {
                        handle: _,
                        status: _,
                        reason: _,
                    } = evt
                    {
                        Ok(WorkResult::GotDisconnected)
                    } else {
                        Ok(WorkResult::DidWork)
                    }
                }
                crate::PollResult::AsyncData(packet) => {
                    let (src_handle, l2cap_packet) = parse_l2cap(packet)?;
                    let packet = parse_att(l2cap_packet)?;
                    info!("att: {:x?}", packet);
                    match packet {
                        Att::ReadByGroupTypeReq {
                            start,
                            end,
                            group_type,
                        } => {
                            self.handle_read_by_group_type_req(src_handle, start, end, group_type);
                        }

                        Att::ReadByTypeReq {
                            start,
                            end,
                            attribute_type,
                        } => {
                            self.handle_read_by_type_req(src_handle, start, end, attribute_type);
                        }

                        Att::ReadReq { handle } => {
                            self.handle_read_req(src_handle, handle);
                        }

                        Att::WriteReq { handle, data } => {
                            self.handle_write_req(src_handle, handle, data);
                        }

                        Att::ExchangeMtu { mtu } => {
                            self.handle_exchange_mtu(src_handle, mtu);
                        }

                        Att::FindByTypeValue {
                            start_handle,
                            end_handle,
                            att_type,
                            att_value,
                        } => {
                            self.handle_find_type_value(
                                src_handle,
                                start_handle,
                                end_handle,
                                att_type,
                                att_value,
                            );
                        }
                    }

                    Ok(WorkResult::DidWork)
                }
            },
        }
    }

    fn handle_read_by_group_type_req(
        &mut self,
        src_handle: u16,
        start: u16,
        end: u16,
        group_type: Uuid,
    ) {
        log::info!("services = {:?}", self.services);

        if group_type == PRIMARY_SERVICE_UUID16 {
            log::info!("Searching for primary service UUIDs");
            // TODO respond with all finds - not just one
            for service in self.services.iter() {
                log::info!("Check service");
                if service.start_handle >= start && service.end_handle <= end {
                    let attribute_list = [AttributeData::new(
                        service.start_handle,
                        service.end_handle,
                        group_type,
                    )];
                    log::info!("found!");
                    self.write_att(
                        src_handle,
                        att_encode_read_by_group_type_response(&attribute_list),
                    );
                    return;
                }
            }
        }

        log::info!("not found");

        // respond with error
        self.write_att(
            src_handle,
            att_encode_error_response(
                ATT_READ_BY_GROUP_TYPE_REQUEST_OPCODE,
                start,
                AttErrorCode::AttributeNotFound,
            ),
        );
    }

    fn handle_read_by_type_req(
        &mut self,
        src_handle: u16,
        start: u16,
        end: u16,
        attribute_type: Uuid,
    ) {
        if attribute_type == CHARACTERISTIC_UUID16 {
            log::info!("Searching for characteristic");
            // TODO respond with all finds - not just one
            for service in self.services.iter() {
                //log::info!("Check service");
                if service.start_handle >= start && service.end_handle <= end {
                    log::info!("Found");
                    let mut data = Data::new(&[
                        service.permissions,
                        // 2 byte handle pointing to characteristic value
                        (service.characteristics_handle & 0xff) as u8,
                        ((service.characteristics_handle & 0xff00) >> 8) as u8,
                        // UUID of characteristic value
                    ]);
                    data.append((&service.uuid).encode().to_slice());

                    let attribute_list =
                        [AttributePayloadData::new(service.start_handle + 1, data)];
                    self.write_att(
                        src_handle,
                        att_encode_read_by_type_response(&attribute_list),
                    );

                    return;
                }
            }
        }

        log::info!("not found");

        // respond with error
        self.write_att(
            src_handle,
            att_encode_error_response(
                ATT_READ_BY_TYPE_REQUEST_OPCODE,
                start,
                AttErrorCode::AttributeNotFound,
            ),
        );
    }

    fn handle_read_req(&mut self, src_handle: u16, handle: u16) {
        let mut answer = None;
        for service in self.services.iter_mut() {
            if service.characteristics_handle == handle {
                answer = Some((*service.read_function)());
                break;
            }
        }

        if let Some(answer) = answer {
            self.write_att(src_handle, att_encode_read_response(&answer));
            return;
        }

        panic!("should create a reasonable error instead of panic");
    }

    fn handle_write_req(&mut self, src_handle: u16, handle: u16, data: Data) {
        let mut found = false;
        for service in self.services.iter_mut() {
            if service.characteristics_handle == handle {
                (*service.write_function)(data);
                found = true;
                break;
            }
        }

        if found {
            self.write_att(src_handle, att_encode_write_response());
            return;
        }

        panic!("should create a reasonable error instead of panic");
    }

    fn handle_exchange_mtu(&mut self, src_handle: u16, mtu: u16) {
        info!("Requested MTU {}, returning 23", mtu);
        self.write_att(src_handle, att_encode_exchange_mtu_response(23));
        return;
    }

    fn handle_find_type_value(
        &mut self,
        src_handle: u16,
        start: u16,
        _end: u16,
        _attr_type: u16,
        _attr_value: u16,
    ) {
        // TODO for now just return an error

        // respond with error
        self.write_att(
            src_handle,
            att_encode_error_response(
                ATT_FIND_BY_TYPE_VALUE_REQUEST_OPCODE,
                start,
                AttErrorCode::AttributeNotFound,
            ),
        );
    }

    fn write_att(&mut self, handle: u16, data: Data) {
        log::info!("src_handle {}", handle);
        log::info!("data {:x?}", data.to_slice());

        let res = encode_l2cap(data);
        log::info!("encoded_l2cap {:x?}", res.to_slice());

        let res = encode_acl_packet(
            handle,
            BoundaryFlag::FirstAutoFlushable,
            HostBroadcastFlag::NoBroadcast,
            res,
        );
        log::info!("writing {:x?}", res.to_slice());
        self.ble.write_bytes(res.to_slice());
    }
}

pub const ATT_READABLE: u8 = 0x02;
pub const ATT_WRITEABLE: u8 = 0x08;

pub struct Service<'a> {
    pub uuid: Uuid,
    pub permissions: u8,
    pub read_function: &'a mut dyn FnMut() -> Data,
    pub write_function: &'a mut dyn FnMut(Data),
    start_handle: u16,
    end_handle: u16,
    characteristics_handle: u16,
}

impl<'a> Service<'a> {
    pub fn new(
        uuid: Uuid,
        permissions: u8,
        read_function: &'a mut dyn FnMut() -> Data,
        write_function: &'a mut dyn FnMut(Data),
    ) -> Service<'a> {
        Service {
            uuid,
            permissions,
            read_function,
            write_function,
            start_handle: 0,
            end_handle: 0,
            characteristics_handle: 0,
        }
    }
}

impl<'a> core::fmt::Debug for Service<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Service")
            .field("uuid", &self.uuid)
            .field("permissions", &self.permissions)
            .field("start_handle", &self.start_handle)
            .field("end_handle", &self.end_handle)
            .field("characteristics_handle", &self.characteristics_handle)
            .finish()
    }
}
