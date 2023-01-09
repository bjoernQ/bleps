use log::info;

use crate::{
    acl::{encode_acl_packet, BoundaryFlag, HostBroadcastFlag},
    att::{
        att_encode_error_response, att_encode_exchange_mtu_response,
        att_encode_execute_write_response, att_encode_find_information_response,
        att_encode_prepare_write_response, att_encode_read_blob_response,
        att_encode_read_by_group_type_response, att_encode_read_by_type_response,
        att_encode_read_response, att_encode_write_response, parse_att, Att, AttErrorCode,
        AttParseError, AttributeData, AttributePayloadData, Uuid,
        ATT_FIND_BY_TYPE_VALUE_REQUEST_OPCODE, ATT_FIND_INFORMATION_REQ_OPCODE,
        ATT_PREPARE_WRITE_REQ_OPCODE, ATT_READ_BLOB_REQ_OPCODE,
        ATT_READ_BY_GROUP_TYPE_REQUEST_OPCODE, ATT_READ_BY_TYPE_REQUEST_OPCODE,
        ATT_READ_REQUEST_OPCODE, ATT_WRITE_REQUEST_OPCODE,
    },
    event::EventType,
    l2cap::{encode_l2cap, parse_l2cap, L2capParseError},
    Ble, Data,
};

pub const PRIMARY_SERVICE_UUID16: Uuid = Uuid::Uuid16(0x2800);
pub const CHARACTERISTIC_UUID16: Uuid = Uuid::Uuid16(0x2803);
pub const GENERIC_ATTRIBUTE_UUID16: Uuid = Uuid::Uuid16(0x1801);

const MTU: u16 = 23;

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
    attributes: &'a mut [Attribute<'a>],
}

impl<'a> AttributeServer<'a> {
    pub fn new(ble: &'a mut Ble<'a>, attributes: &'a mut [Attribute<'a>]) -> AttributeServer<'a> {
        for (i, attr) in attributes.iter_mut().enumerate() {
            attr.handle = i as u16 + 1;
        }

        let mut last_in_group = attributes.last().unwrap().handle;
        for i in (0..attributes.len()).rev() {
            attributes[i].last_handle_in_group = last_in_group;

            if attributes[i].uuid == Uuid::Uuid16(0x2800) && i > 0 {
                last_in_group = attributes[i - 1].handle;
            }
        }

        log::trace!("{:#x?}", &attributes);

        AttributeServer { ble, attributes }
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

                        Att::FindInformation {
                            start_handle,
                            end_handle,
                        } => {
                            self.handle_find_information(src_handle, start_handle, end_handle);
                        }

                        Att::PrepareWriteReq {
                            handle,
                            offset,
                            value,
                        } => {
                            self.handle_prepare_write(src_handle, handle, offset, value);
                        }

                        Att::ExecuteWriteReq { flags } => {
                            self.handle_execute_write(src_handle, flags);
                        }

                        Att::ReadBlobReq { handle, offset } => {
                            self.handle_read_blob(src_handle, handle, offset);
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
        // TODO respond with all finds - not just one
        for att in self.attributes.iter_mut() {
            log::info!("Check attribute {:x?} {}", att.uuid, att.handle);
            if att.uuid == group_type && att.handle >= start && att.handle <= end {
                let attribute_list = [AttributeData::new(
                    att.handle,
                    att.last_handle_in_group,
                    Uuid::from(att.value()),
                )];
                log::info!("found! {:x?}", attribute_list);
                self.write_att(
                    src_handle,
                    att_encode_read_by_group_type_response(&attribute_list),
                );
                return;
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
        // TODO respond with all finds - not just one
        for att in self.attributes.iter_mut() {
            log::info!("Check attribute {:x?} {}", att.uuid, att.handle);
            if att.uuid == attribute_type && att.handle >= start && att.handle <= end {
                let data = match att.data {
                    AttData::Static(bytes) => bytes,
                    AttData::Dynamic {
                        ref mut read_function,
                        ..
                    } => {
                        if let Some(rf) = read_function {
                            (&mut *rf)()
                        } else {
                            &[]
                        }
                    }
                };

                let attribute_list = [AttributePayloadData::new(att.handle, data)];
                log::info!("found! {:x?}", attribute_list);
                self.write_att(
                    src_handle,
                    att_encode_read_by_type_response(&attribute_list),
                );
                return;
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
        for att in self.attributes.iter_mut() {
            if att.handle == handle {
                answer = match att.data {
                    AttData::Static(bytes) => Some(&**bytes),
                    AttData::Dynamic {
                        ref mut read_function,
                        ..
                    } => {
                        if let Some(rf) = read_function {
                            Some((&mut *rf)())
                        } else {
                            None
                        }
                    }
                };
                break;
            }
        }

        if let Some(answer) = answer {
            let len = usize::min(MTU as usize - 1, answer.len() as usize);
            self.write_att(src_handle, att_encode_read_response(&answer[..len]));
            return;
        }

        // respond with error
        self.write_att(
            src_handle,
            att_encode_error_response(
                ATT_READ_REQUEST_OPCODE,
                handle,
                AttErrorCode::AttributeNotFound,
            ),
        );
    }

    fn handle_write_req(&mut self, src_handle: u16, handle: u16, data: Data) {
        let mut found = false;
        for att in self.attributes.iter_mut() {
            if att.handle == handle {
                match att.data {
                    AttData::Static(_bytes) => (),
                    AttData::Dynamic {
                        ref mut write_function,
                        ..
                    } => {
                        if let Some(wf) = write_function {
                            (&mut *wf)(0, &data.to_slice());
                        }
                    }
                };

                found = true;
                break;
            }
        }

        if found {
            self.write_att(src_handle, att_encode_write_response());
            return;
        }

        // respond with error
        self.write_att(
            src_handle,
            att_encode_error_response(
                ATT_WRITE_REQUEST_OPCODE,
                handle,
                AttErrorCode::AttributeNotFound,
            ),
        );
    }

    fn handle_exchange_mtu(&mut self, src_handle: u16, mtu: u16) {
        info!("Requested MTU {}, returning 23", mtu);
        self.write_att(src_handle, att_encode_exchange_mtu_response(MTU));
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

    fn handle_find_information(&mut self, src_handle: u16, start: u16, end: u16) {
        let mut response_data_type: Option<u8> = None;
        let mut result_count = 0;
        let mut result_list: [Option<(u16, Uuid)>; 10] = [None; 10];

        for att in self.attributes.iter_mut() {
            log::info!("Check attribute {:x?} {}", att.uuid, att.handle);
            if att.handle >= start && att.handle <= end {
                if response_data_type.is_none() {
                    response_data_type = Some(att.uuid.get_type());
                }

                if att.uuid.get_type() == response_data_type.unwrap() {
                    result_list[result_count] = Some((att.handle, att.uuid));
                    result_count += 1;
                } else {
                    break;
                }
            }
        }

        if result_count > 0 {
            log::info!("found! {:x?}", &result_list[..result_count]);
            self.write_att(
                src_handle,
                att_encode_find_information_response(
                    response_data_type.unwrap(),
                    &result_list[..result_count],
                ),
            );
            return;
        }

        log::info!("not found");

        // respond with error
        self.write_att(
            src_handle,
            att_encode_error_response(
                ATT_FIND_INFORMATION_REQ_OPCODE,
                start,
                AttErrorCode::AttributeNotFound,
            ),
        );
    }

    fn handle_prepare_write(&mut self, src_handle: u16, handle: u16, offset: u16, value: Data) {
        let mut found = false;
        for att in self.attributes.iter_mut() {
            if att.handle == handle {
                match att.data {
                    AttData::Static(_bytes) => (),
                    AttData::Dynamic {
                        ref mut write_function,
                        ..
                    } => {
                        if let Some(wf) = write_function {
                            (&mut *wf)(offset, value.to_slice());
                        }
                    }
                };

                found = true;
                break;
            }
        }

        if found {
            self.write_att(
                src_handle,
                att_encode_prepare_write_response(handle, offset, value.to_slice()),
            );
            return;
        }

        // respond with error
        self.write_att(
            src_handle,
            att_encode_error_response(
                ATT_PREPARE_WRITE_REQ_OPCODE,
                handle,
                AttErrorCode::AttributeNotFound,
            ),
        );
    }

    fn handle_execute_write(&mut self, src_handle: u16, _flags: u8) {
        // for now we don't do anything here
        self.write_att(src_handle, att_encode_execute_write_response());
    }

    fn handle_read_blob(&mut self, src_handle: u16, handle: u16, offset: u16) {
        let mut answer = None;
        for att in self.attributes.iter_mut() {
            if att.handle == handle {
                answer = match att.data {
                    AttData::Static(bytes) => Some(&**bytes),
                    AttData::Dynamic {
                        ref mut read_function,
                        ..
                    } => {
                        if let Some(rf) = read_function {
                            Some((&mut *rf)())
                        } else {
                            None
                        }
                    }
                };
                break;
            }
        }

        if let Some(answer) = answer {
            let len = usize::min(
                offset as usize + MTU as usize - 1,
                answer.len() as usize + 1,
            ) % MTU as usize
                + 1;
            self.write_att(
                src_handle,
                att_encode_read_blob_response(&answer[offset as usize..][..len]),
            );
            return;
        }

        // respond with error
        self.write_att(
            src_handle,
            att_encode_error_response(
                ATT_READ_BLOB_REQ_OPCODE,
                handle,
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

pub enum AttData<'a> {
    Static(&'a [u8]),
    Dynamic {
        read_function: Option<&'a mut dyn FnMut() -> &'a [u8]>,
        write_function: Option<&'a mut dyn FnMut(u16, &[u8])>,
    },
}

impl<'a> core::fmt::Debug for AttData<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Static(arg0) => f.debug_tuple("Static").field(arg0).finish(),
            Self::Dynamic {
                read_function,
                write_function,
            } => f
                .debug_struct("Dynamic")
                .field("read_function", &read_function.is_some())
                .field("write_function", &write_function.is_some())
                .finish(),
        }
    }
}

#[derive(Debug)]
pub struct Attribute<'a> {
    pub uuid: Uuid,
    pub handle: u16,
    pub data: &'a mut AttData<'a>,
    pub last_handle_in_group: u16,
}

impl<'a> Attribute<'a> {
    pub fn new(uuid: Uuid, data: &'a mut AttData<'a>) -> Attribute<'a> {
        Attribute {
            uuid,
            handle: 0,
            data,
            last_handle_in_group: 0,
        }
    }

    fn value(&mut self) -> &[u8] {
        match self.data {
            AttData::Static(bytes) => bytes,
            AttData::Dynamic {
                ref mut read_function,
                ..
            } => {
                if let Some(rf) = read_function {
                    (&mut *rf)()
                } else {
                    &[]
                }
            }
        }
    }
}
