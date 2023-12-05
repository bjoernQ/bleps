#[cfg(not(feature = "crypto"))]
use core::marker::PhantomData;

use core::cell::RefCell;

use critical_section::Mutex;
use futures::future::Either;
use futures::pin_mut;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "crypto")]
use crate::sm::AsyncSecurityManager;

use crate::{
    asynch::Ble,
    att::Uuid,
    attribute::Attribute,
    attribute_server::{AttributeServerError, NotificationData, WorkResult},
};

pub struct AttributeServer<'a, T, R: CryptoRng + RngCore>
where
    T: embedded_io_async::Read + embedded_io_async::Write,
{
    pub(crate) ble: &'a mut Ble<T>,
    pub(crate) src_handle: u16,
    pub(crate) attributes: &'a mut [Attribute<'a>],

    #[cfg(feature = "crypto")]
    pub(crate) security_manager: AsyncSecurityManager<'a, Ble<T>, R>,

    #[cfg(not(feature = "crypto"))]
    phantom: PhantomData<R>,
}

impl<'a, T, R: CryptoRng + RngCore> AttributeServer<'a, T, R>
where
    T: embedded_io_async::Read + embedded_io_async::Write,
{
    pub fn new(
        ble: &'a mut Ble<T>,
        attributes: &'a mut [Attribute<'a>],
        rng: &'a mut R,
    ) -> AttributeServer<'a, T, R> {
        AttributeServer::new_with_ltk(ble, attributes, [0u8; 6], None, rng)
    }

    /// Create a new instance, optionally provide an LTK
    pub fn new_with_ltk(
        ble: &'a mut Ble<T>,
        attributes: &'a mut [Attribute<'a>],
        _local_addr: [u8; 6],
        _ltk: Option<u128>,
        _rng: &'a mut R,
    ) -> AttributeServer<'a, T, R> {
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

        #[cfg(feature = "crypto")]
        let mut security_manager = AsyncSecurityManager::new(_rng);
        #[cfg(feature = "crypto")]
        {
            security_manager.local_address = Some(_local_addr);
            security_manager.ltk = _ltk;
        }

        AttributeServer {
            ble,
            src_handle: 0,
            attributes,

            #[cfg(feature = "crypto")]
            security_manager,

            #[cfg(not(feature = "crypto"))]
            phantom: PhantomData::default(),
        }
    }

    /// Get the current LTK
    pub fn get_ltk(&self) -> Option<u128> {
        #[cfg(feature = "crypto")]
        return self.security_manager.ltk;

        #[cfg(not(feature = "crypto"))]
        None
    }

    /// Run the GATT server until disconnect
    pub async fn run<F, N>(&mut self, notifier: &'a mut F) -> Result<(), AttributeServerError>
    where
        F: FnMut() -> N,
        N: core::future::Future<Output = NotificationData>,
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
}
