use bleps_macros::gatt;

#[test]
fn test() {
    let mut my_read_function = |_offset: usize, data: &mut [u8]| {
        data[..5].copy_from_slice(&b"Hola!"[..]);
        5
    };
    let mut my_write_function = |_offset, data: &[u8]| {
        println!("{:?}", data);
    };

    gatt!([service {
        uuid: "9e7312e0-2354-11eb-9f10-fbc30a62cf38",
        characteristics: [characteristic {
            uuid: "9e7312e0-2354-11eb-9f10-fbc30a62cf38",
            read: my_read_function,
            write: my_write_function,
        },],
    },]);

    println!("{:x?}", gatt_attributes);
}

#[test]
fn test2() {
    let mut my_read_function = |_offset: usize, data: &mut [u8]| {
        data[..6].copy_from_slice(&b"Hello!"[..]);
        6
    };
    let mut my_write_function = |_offset, data: &[u8]| {
        println!("{:?}", data);
    };

    gatt!([service {
        uuid: "2888",
        characteristics: [characteristic {
            uuid: "1234",
            read: my_read_function,
            write: my_write_function,
        },],
    },]);

    println!("{:x?}", gatt_attributes);
}

#[test]
fn test3() {
    let mut my_read_function = |_offset: usize, data: &mut [u8]| {
        data[..5].copy_from_slice(&b"Hola!"[..]);
        5
    };
    let mut my_write_function = |_offset, data: &[u8]| {
        println!("{:?}", data);
    };

    gatt!([service {
        uuid: "9e7312e0-2354-11eb-9f10-fbc30a62cf38",
        characteristics: [characteristic {
            uuid: "9e7312e0-2354-11eb-9f10-fbc30a62cf38",
            read: my_read_function,
            write: my_write_function,
            description: "something",
        },],
    },]);

    println!("{:x?}", gatt_attributes);
}

#[test]
fn test4() {
    let mut my_read_function = |_offset: usize, data: &mut [u8]| {
        data[..5].copy_from_slice(&b"Hola!"[..]);
        5
    };
    let mut my_write_function = |_offset, data: &[u8]| {
        println!("{:?}", data);
    };

    gatt!([service {
        uuid: "9e7312e0-2354-11eb-9f10-fbc30a62cf38",
        characteristics: [characteristic {
            name: "my_characteristic",
            uuid: "9e7312e0-2354-11eb-9f10-fbc30a62cf38",
            read: my_read_function,
            write: my_write_function,
            description: "something",
            notify: true,
        },],
    },]);

    println!("{:x?}", gatt_attributes);

    println!("{}", my_characteristic_handle);
    println!("{}", my_characteristic_notify_enable_handle);
}
