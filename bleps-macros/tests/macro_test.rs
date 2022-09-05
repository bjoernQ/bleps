use bleps_macros::gatt;

#[test]
fn test() {
    let mut my_read_function = || Data::new(b"Hello");
    let mut my_write_function = |data: Data| {
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
    let mut my_read_function = || Data::new(b"Hello");
    let mut my_write_function = |data: Data| {
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
