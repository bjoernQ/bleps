use core::{fmt, mem::size_of, slice};

use crate::{att::Uuid, Data};

pub trait AttData {
    fn readable(&self) -> bool {
        false
    }

    fn read(&mut self, _offset: usize, _data: &mut [u8]) -> usize {
        0
    }

    fn writable(&self) -> bool {
        false
    }

    fn write(&mut self, _offset: usize, _data: &[u8]) {}
}

impl<'a, const N: usize> AttData for &'a [u8; N] {
    fn readable(&self) -> bool {
        true
    }

    fn read(&mut self, offset: usize, data: &mut [u8]) -> usize {
        if offset > N {
            return 0;
        }
        let len = data.len().min(N - offset);
        if len > 0 {
            data[..len].copy_from_slice(&self[offset..offset + len]);
        }
        len
    }
}

impl<'a, const N: usize> AttData for &'a mut [u8; N] {
    fn readable(&self) -> bool {
        true
    }

    fn read(&mut self, offset: usize, data: &mut [u8]) -> usize {
        if offset > N {
            return 0;
        }
        let len = data.len().min(N - offset);
        if len > 0 {
            data[..len].copy_from_slice(&self[offset..offset + len]);
        }
        len
    }

    fn writable(&self) -> bool {
        true
    }

    fn write(&mut self, offset: usize, data: &[u8]) {
        if offset > N {
            return;
        }
        let len = data.len().min(N - offset);
        if len > 0 {
            self[offset..offset + len].copy_from_slice(&data[..len]);
        }
    }
}

impl<'a> AttData for &'a [u8] {
    fn readable(&self) -> bool {
        true
    }

    fn read(&mut self, offset: usize, data: &mut [u8]) -> usize {
        let len = self.len();
        if offset > len {
            return 0;
        }
        let len = data.len().min(len - offset);
        data[..len].copy_from_slice(&self[offset..offset + len]);
        len
    }
}

impl<'a> AttData for &'a mut [u8] {
    fn readable(&self) -> bool {
        true
    }

    fn read(&mut self, offset: usize, data: &mut [u8]) -> usize {
        let len = self.len();
        if offset > len {
            return 0;
        }
        let len = data.len().min(len - offset);
        data[..len].copy_from_slice(&self[offset..offset + len]);
        len
    }

    fn writable(&self) -> bool {
        true
    }

    fn write(&mut self, offset: usize, data: &[u8]) {
        let len = self.len();
        if offset > len {
            return;
        }
        let len = data.len().min(len - offset);
        self[offset..offset + len].copy_from_slice(&data[..len]);
    }
}

impl<'a, T: Sized + 'static> AttData for &'a (T,) {
    fn readable(&self) -> bool {
        true
    }

    fn read(&mut self, offset: usize, data: &mut [u8]) -> usize {
        if offset > size_of::<T>() {
            return 0;
        }
        let len = data.len().min(size_of::<T>() - offset);
        if len > 0 {
            let slice =
                unsafe { slice::from_raw_parts(&self.0 as *const T as *const u8, size_of::<T>()) };
            // TODO: Handle big endian case
            data[..len].copy_from_slice(&slice[offset..offset + len]);
        }
        len
    }
}

impl<'a, T: Sized + 'static> AttData for &'a mut (T,) {
    fn readable(&self) -> bool {
        true
    }

    fn read(&mut self, offset: usize, data: &mut [u8]) -> usize {
        if offset > size_of::<T>() {
            return 0;
        }
        let len = data.len().min(size_of::<T>() - offset);
        if len > 0 {
            let slice =
                unsafe { slice::from_raw_parts(&self.0 as *const T as *const u8, size_of::<T>()) };
            // TODO: Handle big endian case
            data[..len].copy_from_slice(&slice[offset..offset + len]);
        }
        len
    }

    fn writable(&self) -> bool {
        true
    }

    fn write(&mut self, offset: usize, data: &[u8]) {
        if offset > size_of::<T>() {
            return;
        }
        let len = data.len().min(size_of::<T>() - offset);
        if len > 0 {
            let slice = unsafe {
                slice::from_raw_parts_mut(&mut self.0 as *mut T as *mut u8, size_of::<T>())
            };
            // TODO: Handle big endian case
            slice[offset..offset + len].copy_from_slice(&data[..len]);
        }
    }
}

impl<R> AttData for (R, ())
where
    R: FnMut(usize, &mut [u8]) -> usize,
{
    fn readable(&self) -> bool {
        true
    }

    fn read(&mut self, offset: usize, data: &mut [u8]) -> usize {
        self.0(offset, data)
    }
}

impl<W> AttData for ((), W)
where
    W: FnMut(usize, &[u8]),
{
    fn writable(&self) -> bool {
        true
    }

    fn write(&mut self, offset: usize, data: &[u8]) {
        self.1(offset, data);
    }
}

impl<R, W> AttData for (R, W)
where
    R: FnMut(usize, &mut [u8]) -> usize,
    W: FnMut(usize, &[u8]),
{
    fn readable(&self) -> bool {
        true
    }

    fn read(&mut self, offset: usize, data: &mut [u8]) -> usize {
        self.0(offset, data)
    }

    fn writable(&self) -> bool {
        true
    }

    fn write(&mut self, offset: usize, data: &[u8]) {
        self.1(offset, data);
    }
}

pub const ATT_READABLE: u8 = 0x02;
pub const ATT_WRITEABLE: u8 = 0x08;

pub struct Attribute<'a> {
    pub uuid: Uuid,
    pub handle: u16,
    pub data: &'a mut dyn AttData,
    pub last_handle_in_group: u16,
}

impl<'a> fmt::Debug for Attribute<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attribute")
            .field("uuid", &self.uuid)
            .field("handle", &self.handle)
            .field("last_handle_in_group", &self.last_handle_in_group)
            .field("readable", &self.data.readable())
            .field("writable", &self.data.writable())
            .finish()
    }
}

impl<'a> Attribute<'a> {
    pub fn new(uuid: Uuid, data: &'a mut impl AttData) -> Attribute<'a> {
        Attribute {
            uuid,
            handle: 0,
            data,
            last_handle_in_group: 0,
        }
    }

    pub(crate) fn value(&mut self) -> Data {
        let mut data = Data::default();
        if self.data.readable() {
            let len = self.data.read(0, data.as_slice_mut());
            data.append_len(len);
        }
        data
    }
}
