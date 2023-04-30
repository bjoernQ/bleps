use core::cell::RefCell;

use critical_section::Mutex;
use futures::future::Either;
use futures::pin_mut;
use log::info;

use crate::{
    acl::{encode_acl_packet, BoundaryFlag, HostBroadcastFlag},
    asynch::Ble,
    att::{
        parse_att, Att, AttErrorCode, Uuid, ATT_FIND_BY_TYPE_VALUE_REQUEST_OPCODE,
        ATT_FIND_INFORMATION_REQ_OPCODE, ATT_PREPARE_WRITE_REQ_OPCODE, ATT_READ_BLOB_REQ_OPCODE,
        ATT_READ_BY_GROUP_TYPE_REQUEST_OPCODE, ATT_READ_BY_TYPE_REQUEST_OPCODE,
        ATT_READ_REQUEST_OPCODE, ATT_WRITE_REQUEST_OPCODE,
    },
    attribute::Attribute,
    attribute_server::{AttributeServerError, NotificationData, WorkResult, MTU},
    check_command_completed,
    command::{create_command_data, Command, LE_OGF, SET_ADVERTISING_DATA_OCF},
    event::EventType,
    l2cap::{encode_l2cap, parse_l2cap},
    Data, Error,
};

pub struct AttributeServer<'a, T>
where
    T: embedded_io::asynch::Read + embedded_io::asynch::Write,
{
    ble: &'a mut Ble<T>,
    src_handle: u16,
    attributes: &'a mut [Attribute<'a>],
}

impl<'a, T> AttributeServer<'a, T>
where
    T: embedded_io::asynch::Read + embedded_io::asynch::Write,
{
    pub fn new(ble: &'a mut Ble<T>, attributes: &'a mut [Attribute<'a>]) -> AttributeServer<'a, T> {
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

    pub async fn update_le_advertising_data(&mut self, data: Data) -> Result<EventType, Error> {
        self.ble
            .write_bytes(create_command_data(Command::LeSetAdvertisingData { data }).as_slice())
            .await;
        check_command_completed(
            self.ble
                .wait_for_command_complete(LE_OGF, SET_ADVERTISING_DATA_OCF)
                .await?,
        )
    }

    pub async fn disconnect(&mut self, reason: u8) -> Result<EventType, Error> {
        self.ble
            .write_bytes(
                create_command_data(Command::Disconnect {
                    connection_handle: 0,
                    reason,
                })
                .as_slice(),
            )
            .await;
        Ok(EventType::Unknown)
    }

    /// Run the GATT server until disconnect
    pub async fn run<F, R>(&mut self, notifier: &'a mut F) -> Result<(), AttributeServerError>
    where
        F: FnMut() -> R,
        R: core::future::Future<Output = NotificationData>,
    {
        let notification_to_send = Mutex::new(RefCell::new(None));
        loop {
            let notifier_future = async { notifier().await };
            let worker_future = async {
                let notification: Option<NotificationData> =
                    critical_section::with(|cs| notification_to_send.borrow_ref_mut(cs).take());

                // check if notifications are enabled for the characteristic handle
                let notification = if let Some(notification) = notification {
                    let attr = self
                        .attributes
                        .iter()
                        .enumerate()
                        .find(|(_idx, attr)| attr.handle == notification.handle);
                    let enabled = if let Some((idx, _)) = attr {
                        // assume the next descriptor is the "Client Characteristic Configuration" Descriptor
                        // which is always true when using the macro
                        if self.attributes.len() > idx + 1
                            && self.attributes[idx + 1].uuid == Uuid::Uuid16(0x2902)
                        {
                            let mut cccd = [0u8; 1];
                            let cccd_len =
                                self.get_characteristic_value((idx + 1) as u16, 0, &mut cccd[..]);
                            if let Some(1) = cccd_len {
                                cccd[0] == 1
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    };
                    if enabled {
                        Some(notification)
                    } else {
                        None
                    }
                } else {
                    None
                };

                self.do_work_with_notification(notification).await
            };
            pin_mut!(notifier_future);
            pin_mut!(worker_future);

            let notification = match futures::future::select(notifier_future, worker_future).await {
                Either::Left((notification, _)) => Some(notification),
                Either::Right((value, _)) => {
                    if value? == WorkResult::GotDisconnected {
                        break;
                    }
                    None
                }
            };

            if let Some(notification) = notification {
                critical_section::with(|cs| {
                    notification_to_send
                        .borrow_ref_mut(cs)
                        .replace(notification);
                });
            }
        }

        Ok(())
    }

    pub async fn do_work(&mut self) -> Result<WorkResult, AttributeServerError> {
        self.do_work_with_notification(None).await
    }

    pub async fn do_work_with_notification(
        &mut self,
        notification_data: Option<NotificationData>,
    ) -> Result<WorkResult, AttributeServerError> {
        if let Some(notification_data) = notification_data {
            let mut answer = notification_data.data;
            answer.limit_len(MTU as usize - 3);
            let mut data = Data::new_att_value_ntf(notification_data.handle);
            data.append(&answer.as_slice());
            self.write_att(self.src_handle, data).await;
        }

        let packet = self.ble.poll().await;

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
                            self.handle_read_by_group_type_req(src_handle, start, end, group_type)
                                .await;
                        }

                        Att::ReadByTypeReq {
                            start,
                            end,
                            attribute_type,
                        } => {
                            self.handle_read_by_type_req(src_handle, start, end, attribute_type)
                                .await;
                        }

                        Att::ReadReq { handle } => {
                            self.handle_read_req(src_handle, handle).await;
                        }

                        Att::WriteReq { handle, data } => {
                            self.src_handle = src_handle;
                            self.handle_write_req(src_handle, handle, data).await;
                        }

                        Att::ExchangeMtu { mtu } => {
                            self.handle_exchange_mtu(src_handle, mtu).await;
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
                            )
                            .await;
                        }

                        Att::FindInformation {
                            start_handle,
                            end_handle,
                        } => {
                            self.handle_find_information(src_handle, start_handle, end_handle)
                                .await;
                        }

                        Att::PrepareWriteReq {
                            handle,
                            offset,
                            value,
                        } => {
                            self.handle_prepare_write(src_handle, handle, offset, value)
                                .await;
                        }

                        Att::ExecuteWriteReq { flags } => {
                            self.handle_execute_write(src_handle, flags).await;
                        }

                        Att::ReadBlobReq { handle, offset } => {
                            self.handle_read_blob(src_handle, handle, offset).await;
                        }
                    }

                    Ok(WorkResult::DidWork)
                }
            },
        }
    }

    async fn handle_read_by_group_type_req(
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
                let mut data = Data::new_att_read_by_group_type_response();
                log::info!("found! {:x?}", att.handle);
                data.append_att_read_by_group_type_response(
                    att.handle,
                    att.last_handle_in_group,
                    &Uuid::from(att.value()),
                );
                self.write_att(src_handle, data).await;
                return;
            }
        }

        log::info!("not found");

        // respond with error
        self.write_att(
            src_handle,
            Data::new_att_error_response(
                ATT_READ_BY_GROUP_TYPE_REQUEST_OPCODE,
                start,
                AttErrorCode::AttributeNotFound,
            ),
        )
        .await;
    }

    async fn handle_read_by_type_req(
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
                let mut data = Data::new_att_read_by_type_response();
                data.append_value(att.handle);

                if att.data.readable() {
                    let len = att.data.read(0, data.as_slice_mut());
                    data.append_len(len);
                }
                data.append_att_read_by_type_response();

                log::info!("found! {:x?} {}", att.uuid, att.handle);
                self.write_att(src_handle, data).await;
                return;
            }
        }

        log::info!("not found");
        // respond with error
        self.write_att(
            src_handle,
            Data::new_att_error_response(
                ATT_READ_BY_TYPE_REQUEST_OPCODE,
                start,
                AttErrorCode::AttributeNotFound,
            ),
        )
        .await;
    }

    async fn handle_read_req(&mut self, src_handle: u16, handle: u16) {
        let mut data = Data::new_att_read_response();

        for att in self.attributes.iter_mut() {
            if att.handle == handle {
                if att.handle == handle {
                    if att.data.readable() {
                        let len = att.data.read(0, data.as_slice_mut());
                        data.append_len(len);
                    }
                    break;
                }
                break;
            }
        }

        if data.has_att_read_response_data() {
            data.limit_len(MTU as usize);
            self.write_att(src_handle, data).await;
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
        )
        .await;
    }

    async fn handle_write_req(&mut self, src_handle: u16, handle: u16, data: Data) {
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
            self.write_att(src_handle, Data::new_att_write_response())
                .await;
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
        )
        .await;
    }

    async fn handle_exchange_mtu(&mut self, src_handle: u16, mtu: u16) {
        info!("Requested MTU {}, returning 23", mtu);
        self.write_att(src_handle, Data::new_att_exchange_mtu_response(MTU))
            .await;
        return;
    }

    async fn handle_find_type_value(
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
        )
        .await;
    }

    async fn handle_find_information(&mut self, src_handle: u16, start: u16, end: u16) {
        let mut data = Data::new_att_find_information_response();

        for att in self.attributes.iter_mut() {
            log::info!("Check attribute {:x?} {}", att.uuid, att.handle);
            if att.handle >= start && att.handle <= end {
                if !data.append_att_find_information_response(att.handle, &att.uuid) {
                    break;
                }
                log::info!("found! {:x?} {}", att.uuid, att.handle);
            }
        }

        if data.has_att_find_information_response_data() {
            self.write_att(src_handle, data).await;
            return;
        }

        log::info!("not found");

        // respond with error
        self.write_att(
            src_handle,
            Data::new_att_error_response(
                ATT_FIND_INFORMATION_REQ_OPCODE,
                start,
                AttErrorCode::AttributeNotFound,
            ),
        )
        .await;
    }

    async fn handle_prepare_write(
        &mut self,
        src_handle: u16,
        handle: u16,
        offset: u16,
        value: Data,
    ) {
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
            self.write_att(src_handle, data).await;
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
        )
        .await;
    }

    async fn handle_execute_write(&mut self, src_handle: u16, _flags: u8) {
        // for now we don't do anything here
        self.write_att(src_handle, Data::new_att_execute_write_response())
            .await;
    }

    async fn handle_read_blob(&mut self, src_handle: u16, handle: u16, offset: u16) {
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
            self.write_att(src_handle, data).await;
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
        )
        .await;
    }

    async fn write_att(&mut self, handle: u16, data: Data) {
        log::info!("src_handle {}", handle);
        log::info!("data {:x?}", data.as_slice());

        let res = encode_l2cap(data);
        log::info!("encoded_l2cap {:x?}", res.as_slice());

        let res = encode_acl_packet(
            handle,
            BoundaryFlag::FirstAutoFlushable,
            HostBroadcastFlag::NoBroadcast,
            res,
        );
        log::info!("writing {:x?}", res.as_slice());
        self.ble.write_bytes(res.as_slice()).await;
    }
}