use crate::{
    acl::{encode_acl_packet, BoundaryFlag, HostBroadcastFlag},
    att::{
        parse_att, Att, AttErrorCode, AttParseError, Uuid, ATT_FIND_BY_TYPE_VALUE_REQUEST_OPCODE,
        ATT_FIND_INFORMATION_REQ_OPCODE, ATT_PREPARE_WRITE_REQ_OPCODE, ATT_READ_BLOB_REQ_OPCODE,
        ATT_READ_BY_GROUP_TYPE_REQUEST_OPCODE, ATT_READ_BY_TYPE_REQUEST_OPCODE,
        ATT_READ_REQUEST_OPCODE, ATT_WRITE_REQUEST_OPCODE,
    },
    attribute::Attribute,
    check_command_completed,
    command::{create_command_data, Command, LE_OGF, SET_ADVERTISING_DATA_OCF},
    event::EventType,
    l2cap::{encode_l2cap, parse_l2cap, L2capParseError},
    Ble, Data, Error,
};

pub const PRIMARY_SERVICE_UUID16: Uuid = Uuid::Uuid16(0x2800);
pub const CHARACTERISTIC_UUID16: Uuid = Uuid::Uuid16(0x2803);
pub const GENERIC_ATTRIBUTE_UUID16: Uuid = Uuid::Uuid16(0x1801);

pub const MTU: u16 = 23;

#[derive(Debug, PartialEq)]
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
    src_handle: u16,
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

        AttributeServer {
            ble,
            src_handle: 0,
            attributes,
        }
    }

    pub fn get_characteristic_value(
        &mut self,
        handle: u16,
        offset: u16,
        buffer: &mut [u8],
    ) -> Option<usize> {
        let att = &mut self.attributes[handle as usize];

        if att.data.readable() {
            Some(att.data.read(offset as usize, buffer))
        } else {
            None
        }
    }

    pub fn update_le_advertising_data(&mut self, data: Data) -> Result<EventType, Error> {
        self.ble
            .write_bytes(create_command_data(Command::LeSetAdvertisingData { data }).as_slice());
        check_command_completed(
            self.ble
                .wait_for_command_complete(LE_OGF, SET_ADVERTISING_DATA_OCF)?,
        )
    }

    pub fn disconnect(&mut self, reason: u8) -> Result<EventType, Error> {
        self.ble.write_bytes(
            create_command_data(Command::Disconnect {
                connection_handle: 0,
                reason,
            })
            .as_slice(),
        );
        Ok(EventType::Unknown)
    }

    pub fn do_work(&mut self) -> Result<WorkResult, AttributeServerError> {
        self.do_work_with_notification(None)
    }

    pub fn do_work_with_notification(
        &mut self,
        notification_data: Option<NotificationData>,
    ) -> Result<WorkResult, AttributeServerError> {
        if let Some(notification_data) = notification_data {
            let mut answer = notification_data.data;
            answer.limit_len(MTU as usize - 3);
            let mut data = Data::new_att_value_ntf(notification_data.handle);
            data.append(&answer.as_slice());
            self.write_att(self.src_handle, data);
        }

        let packet = self.ble.poll();

        if packet.is_some() {
            log::trace!("polled: {:?}", packet);
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
                    log::trace!("att: {:x?}", packet);
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
                            self.src_handle = src_handle;
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
            log::trace!("Check attribute {:x?} {}", att.uuid, att.handle);
            if att.uuid == group_type && att.handle >= start && att.handle <= end {
                let mut data = Data::new_att_read_by_group_type_response();
                log::debug!("found! {:x?}", att.handle);
                data.append_att_read_by_group_type_response(
                    att.handle,
                    att.last_handle_in_group,
                    &Uuid::from(att.value()),
                );
                self.write_att(src_handle, data);
                return;
            }
        }

        log::debug!("not found");

        // respond with error
        self.write_att(
            src_handle,
            Data::new_att_error_response(
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
            log::trace!("Check attribute {:x?} {}", att.uuid, att.handle);
            if att.uuid == attribute_type && att.handle >= start && att.handle <= end {
                let mut data = Data::new_att_read_by_type_response();
                data.append_value(att.handle);

                if att.data.readable() {
                    let len = att.data.read(0, data.as_slice_mut());
                    data.append_len(len);
                }
                data.append_att_read_by_type_response();

                log::debug!("found! {:x?} {}", att.uuid, att.handle);
                self.write_att(src_handle, data);
                return;
            }
        }

        log::debug!("not found");
        // respond with error
        self.write_att(
            src_handle,
            Data::new_att_error_response(
                ATT_READ_BY_TYPE_REQUEST_OPCODE,
                start,
                AttErrorCode::AttributeNotFound,
            ),
        );
    }

    fn handle_read_req(&mut self, src_handle: u16, handle: u16) {
        let mut data = Data::new_att_read_response();

        for att in self.attributes.iter_mut() {
            if att.handle == handle {
                if att.data.readable() {
                    let len = att.data.read(0, data.as_slice_mut());
                    data.append_len(len);
                }
                break;
            }
        }

        if data.has_att_read_response_data() {
            data.limit_len(MTU as usize);
            self.write_att(src_handle, data);
            return;
        }

        // respond with error
        self.write_att(
            src_handle,
            Data::new_att_error_response(
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
                if att.data.writable() {
                    att.data.write(0, &data.as_slice());
                }
                found = true;
                break;
            }
        }

        if found {
            self.write_att(src_handle, Data::new_att_write_response());
            return;
        }

        // respond with error
        self.write_att(
            src_handle,
            Data::new_att_error_response(
                ATT_WRITE_REQUEST_OPCODE,
                handle,
                AttErrorCode::AttributeNotFound,
            ),
        );
    }

    fn handle_exchange_mtu(&mut self, src_handle: u16, mtu: u16) {
        log::debug!("Requested MTU {}, returning 23", mtu);
        self.write_att(src_handle, Data::new_att_exchange_mtu_response(MTU));
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
            Data::new_att_error_response(
                ATT_FIND_BY_TYPE_VALUE_REQUEST_OPCODE,
                start,
                AttErrorCode::AttributeNotFound,
            ),
        );
    }

    fn handle_find_information(&mut self, src_handle: u16, start: u16, end: u16) {
        let mut data = Data::new_att_find_information_response();

        for att in self.attributes.iter_mut() {
            log::trace!("Check attribute {:x?} {}", att.uuid, att.handle);
            if att.handle >= start && att.handle <= end {
                if att.handle >= start && att.handle <= end {
                    if !data.append_att_find_information_response(att.handle, &att.uuid) {
                        break;
                    }
                    log::debug!("found! {:x?} {}", att.uuid, att.handle);
                }
            }
        }

        if data.has_att_find_information_response_data() {
            self.write_att(src_handle, data);
            return;
        }

        log::debug!("not found");

        // respond with error
        self.write_att(
            src_handle,
            Data::new_att_error_response(
                ATT_FIND_INFORMATION_REQ_OPCODE,
                start,
                AttErrorCode::AttributeNotFound,
            ),
        );
    }

    fn handle_prepare_write(&mut self, src_handle: u16, handle: u16, offset: u16, value: Data) {
        let mut data = Data::new_att_prepare_write_response(handle, offset);

        for att in self.attributes.iter_mut() {
            if att.handle == handle {
                if att.data.writable() {
                    att.data.write(offset as usize, value.as_slice());
                }
                data.append(value.as_slice());
                break;
            }
        }

        if data.has_att_prepare_write_response_data() {
            self.write_att(src_handle, data);
            return;
        }

        // respond with error
        self.write_att(
            src_handle,
            Data::new_att_error_response(
                ATT_PREPARE_WRITE_REQ_OPCODE,
                handle,
                AttErrorCode::AttributeNotFound,
            ),
        );
    }

    fn handle_execute_write(&mut self, src_handle: u16, _flags: u8) {
        // for now we don't do anything here
        self.write_att(src_handle, Data::new_att_execute_write_response());
    }

    fn handle_read_blob(&mut self, src_handle: u16, handle: u16, offset: u16) {
        let mut data = Data::new_att_read_blob_response();

        for att in self.attributes.iter_mut() {
            if att.handle == handle {
                if att.data.readable() {
                    let len = att.data.read(offset as usize, data.as_slice_mut());
                    data.append_len(len);
                }
                break;
            }
        }

        if data.has_att_read_blob_response_data() {
            data.limit_len(MTU as usize - 1);
            self.write_att(src_handle, data);
            return;
        }

        // respond with error
        self.write_att(
            src_handle,
            Data::new_att_error_response(
                ATT_READ_BLOB_REQ_OPCODE,
                handle,
                AttErrorCode::AttributeNotFound,
            ),
        );
    }

    fn write_att(&mut self, handle: u16, data: Data) {
        log::debug!("src_handle {}", handle);
        log::debug!("data {:x?}", data.as_slice());

        let res = encode_l2cap(data);
        log::trace!("encoded_l2cap {:x?}", res.as_slice());

        let res = encode_acl_packet(
            handle,
            BoundaryFlag::FirstAutoFlushable,
            HostBroadcastFlag::NoBroadcast,
            res,
        );
        log::trace!("writing {:x?}", res.as_slice());
        self.ble.write_bytes(res.as_slice());
    }
}

#[derive(Debug)]
pub struct NotificationData {
    pub(crate) handle: u16,
    pub(crate) data: Data,
}

impl NotificationData {
    pub fn new(handle: u16, data: &[u8]) -> Self {
        Self {
            handle,
            data: Data::new(data),
        }
    }
}
