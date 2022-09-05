use bleps::Data;
use bleps_macros::gatt;

use bleps::att::Uuid;
use bleps::attribute_server::AttData;
use bleps::attribute_server::Attribute;
use bleps::attribute_server::CHARACTERISTIC_UUID16;
use bleps::attribute_server::PRIMARY_SERVICE_UUID16;

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

    println!("{:?}", attributes);
    panic!();
}
