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

#[test]
fn test5() {
    let char_value = b"Hello!";

    let mut my_read_function = |_offset: usize, data: &mut [u8]| {
        data[..5].copy_from_slice(&b"Hola!"[..]);
        5
    };
    let mut my_write_function = |_offset, data: &[u8]| {
        println!("{:?}", data);
    };

    let desc_value = b"Hallo!";

    gatt!([service {
        uuid: "9e7312e0-2354-11eb-9f10-fbc30a62cf38",
        characteristics: [characteristic {
            uuid: "9e7312e0-2354-11eb-9f10-fbc30a62cf38",
            value: char_value,
            descriptors: [
                descriptor {
                    uuid: "9e7312e0-0001-11eb-9f10-fbc30a62cf38",
                    read: my_read_function,
                    write: my_write_function,
                },
                descriptor {
                    uuid: "9e7312e0-0002-11eb-9f10-fbc30a62cf38",
                    value: desc_value,
                },
            ],
        },],
    },]);

    println!("{:x?}", gatt_attributes);
}

#[test]
fn test6() {
    let mut my_read_function = |_offset: usize, data: &mut [u8]| {
        data[..5].copy_from_slice(&b"Ciao!"[..]);
        5
    };
    let mut my_write_function = |_offset, data: &[u8]| {
        println!("{:?}", data);
    };
    let mut my_notify = |enabled: bool| {
        println!("enabled = {enabled}");
    };

    gatt!([service {
        uuid: "9e7312e0-2354-11eb-9f10-fbc30a62cf38",
        characteristics: [characteristic {
            uuid: "9e7312e0-2354-11eb-9f10-fbc30a62cf38",
            notify: true,
            notify_cb: my_notify,
            read: my_read_function,
            write: my_write_function,
        },],
    },]);

    println!("{:x?}", gatt_attributes);
}
