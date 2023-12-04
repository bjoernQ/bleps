use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, Expr, Lit, Member, Path};

/// Creates an array named `gatt_attributes` defining the given services
///
/// ```no-execute
/// gatt!([
///     service {
///         uuid: "9e7312e0-2354-11eb-9f10-fbc30a62cf38",
///         characteristics: [
///             characteristic {
///                 uuid: "ed5a3953-8ea8-4e0c-9675-044de805a719",
///                 read: my_read_function,
///                 write: my_write_function,
///                 name: "characteristic1",
///                 description: "Characteristic accessible via functions",
///             },
///             characteristic {
///                 uuid: "96c05dff-2ff0-4080-ab41-f4d24bc6da85",
///                 value: my_data,
///                 name: "characteristic2",
///                 description: "Characteristic with value which implements AttData",
///             },
///         ],
///     },
/// ]);
/// ```
///
#[proc_macro]
pub fn gatt(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as syn::ExprArray);

    let mut services: Vec<Service> = Vec::new();

    for elem in ast.elems {
        match elem {
            syn::Expr::Struct(s) => {
                if path_to_string(s.path) != "service" {
                    return quote! { compile_error!("Unexpected"); }.into();
                }

                let mut service = Service::default();

                for field in s.fields {
                    let name = if let Member::Named(name) = field.member {
                        name.to_string()
                    } else {
                        return quote! { compile_error!("Unexpected"); }.into();
                    };

                    match name.as_str() {
                        "uuid" => {
                            if let Expr::Lit(value) = field.expr {
                                if let Lit::Str(s) = value.lit {
                                    service.uuid = s.value();
                                } else {
                                    return quote! { compile_error!("Unexpected"); }.into();
                                }
                            } else {
                                return quote! { compile_error!("Unexpected"); }.into();
                            }
                        }
                        "characteristics" => {
                            if let Expr::Array(characteristics) = field.expr {
                                for characteristic in characteristics.elems {
                                    if let Expr::Struct(s) = characteristic {
                                        if path_to_string(s.path) != "characteristic" {
                                            return quote! { compile_error!("Unexpected"); }.into();
                                        }

                                        let mut charact = Characteristic::default();

                                        for field in s.fields {
                                            let name = if let Member::Named(name) = field.member {
                                                name.to_string()
                                            } else {
                                                return quote! { compile_error!("Unexpected"); }
                                                    .into();
                                            };

                                            match name.as_str() {
                                                "uuid" => {
                                                    if let Expr::Lit(value) = field.expr {
                                                        if let Lit::Str(s) = value.lit {
                                                            charact.uuid = s.value();
                                                        } else {
                                                            return quote!{ compile_error!("Unexpected"); }.into();
                                                        }
                                                    } else {
                                                        return quote!{ compile_error!("Unexpected"); }.into();
                                                    }
                                                }
                                                "data" => {
                                                    if let Expr::Path(p) = field.expr {
                                                        let name = path_to_string(p.path);
                                                        charact.data = Some(name);
                                                    } else {
                                                        return quote!{ compile_error!("Unexpected"); }.into();
                                                    }
                                                }
                                                "value" => {
                                                    if let Expr::Path(p) = field.expr {
                                                        let name = path_to_string(p.path);
                                                        charact.value = Some(name);
                                                    } else {
                                                        return quote!{ compile_error!("Unexpected"); }.into();
                                                    }
                                                }
                                                "read" => {
                                                    if let Expr::Path(p) = field.expr {
                                                        let name = path_to_string(p.path);
                                                        charact.read = Some(name);
                                                    } else {
                                                        return quote!{ compile_error!("Unexpected"); }.into();
                                                    }
                                                }
                                                "write" => {
                                                    if let Expr::Path(p) = field.expr {
                                                        let name = path_to_string(p.path);
                                                        charact.write = Some(name);
                                                    } else {
                                                        return quote!{ compile_error!("Unexpected"); }.into();
                                                    }
                                                }
                                                "description" => {
                                                    if let Expr::Lit(value) = field.expr {
                                                        if let Lit::Str(s) = value.lit {
                                                            charact.description = Some(s.value());
                                                        } else {
                                                            return quote!{ compile_error!("Unexpected"); }.into();
                                                        }
                                                    } else {
                                                        return quote!{ compile_error!("Unexpected"); }.into();
                                                    }
                                                }
                                                "notify" => {
                                                    if let Expr::Lit(value) = field.expr {
                                                        if let Lit::Bool(s) = value.lit {
                                                            charact.notify = s.value();
                                                        } else {
                                                            return quote!{ compile_error!("Unexpected"); }.into();
                                                        }
                                                    } else {
                                                        return quote!{ compile_error!("Unexpected"); }.into();
                                                    }
                                                }
                                                "name" => {
                                                    if let Expr::Lit(value) = field.expr {
                                                        if let Lit::Str(s) = value.lit {
                                                            charact.name = Some(s.value());
                                                        } else {
                                                            return quote!{ compile_error!("Unexpected"); }.into();
                                                        }
                                                    } else {
                                                        return quote!{ compile_error!("Unexpected"); }.into();
                                                    }
                                                }
                                                _ => {
                                                    return quote! { compile_error!("Unexpected"); }
                                                        .into()
                                                }
                                            }
                                        }

                                        service.characteristics.push(charact);
                                    } else {
                                        return quote! { compile_error!("Unexpected"); }.into();
                                    }
                                }
                            } else {
                                return quote! { compile_error!("Unexpected"); }.into();
                            }
                        }
                        _ => return quote! { compile_error!("Unexpected"); }.into(),
                    }
                }

                services.push(service);
            }
            _ => return quote! { compile_error!("Unexpected"); }.into(),
        };
    }

    let mut decls: Vec<_> = Vec::new();
    let mut attribs: Vec<_> = Vec::new();
    let mut post: Vec<_> = Vec::new();
    let mut pre: Vec<_> = Vec::new();
    let mut current_handle: usize = 0;
    for (i, service) in services.iter().enumerate() {
        let uuid_bytes = uuid_to_bytes(&service.uuid);
        let uuid_ident = format_ident!("_uuid{}", i);

        decls.push(quote!(let #uuid_ident = [ #(#uuid_bytes),* ] ;));

        let uuid_data = format_ident!("_uuid_data{}", i);
        decls.push(quote!(let mut #uuid_data = &#uuid_ident;));

        let primary_service_ident = format_ident!("_primary_srv{}", i);
        decls.push(
            quote!(let #primary_service_ident = Attribute::new(PRIMARY_SERVICE_UUID16, &mut #uuid_data);)
        );

        attribs.push(quote!(#primary_service_ident));
        current_handle += 1;

        for (j, characteristic) in service.characteristics.iter().enumerate() {
            let mut char_data: Vec<u8> = Vec::new();
            char_data.push(
                if characteristic.read.is_some() {
                    0x02
                } else {
                    0
                } | if characteristic.write.is_some() {
                    0x08
                } else {
                    0
                } | if characteristic.notify { 0x10 } else { 0 },
            );

            let char_handle = (attribs.len() + 1 + 1) as u16;
            char_data.extend(char_handle.to_le_bytes());
            let uuid_bytes = uuid_to_bytes(&characteristic.uuid);
            char_data.extend(uuid_bytes.clone());
            let char_data_ident = format_ident!("_char_data{}{}", i, j);
            decls.push(quote!(let #char_data_ident = [ #(#char_data),* ] ;));

            let char_data_attr = format_ident!("_char_data_attr{}{}", i, j);
            decls.push(quote!(let mut #char_data_attr = &#char_data_ident;));

            let char_data_attribute = format_ident!("_char_data_attribute{}{}", i, j);
            decls.push(
                quote!(let #char_data_attribute = Attribute::new(CHARACTERISTIC_UUID16, &mut #char_data_attr);)
            );
            attribs.push(quote!(#char_data_attribute));
            current_handle += 1;

            let gen_attr_att_data_ident = format_ident!("_gen_attr_att_data{}{}", i, j);

            decls.push(
                if characteristic.read.is_some() || characteristic.write.is_some() {
                    let rfunction = if let Some(name) = &characteristic.read {
                        let fname = format_ident!("{}", name);
                        quote!(&mut #fname)
                    } else {
                        quote!(())
                    };

                    let wfunction = if let Some(name) = &characteristic.write {
                        let fname = format_ident!("{}", name);
                        quote!(&mut #fname)
                    } else {
                        quote!(())
                    };

                    quote!(let mut #gen_attr_att_data_ident = (#rfunction, #wfunction);)
                } else if let Some(name) = &characteristic.value {
                    let vname = format_ident!("{}", name);
                    quote!(let mut #gen_attr_att_data_ident = (#vname,);)
                } else if let Some(name) = &characteristic.data {
                    let dname = format_ident!("{}", name);
                    quote!(let mut #gen_attr_att_data_ident = (#dname,);)
                } else {
                    quote!(compile_error!(
                        "Characteristic data fields missing: 'read'/'write' nor 'value' nor 'data'"
                    ))
                },
            );

            let gen_attr_ident = format_ident!("_gen_attr{}{}", i, j);
            let gen_attr_att_uuid = if uuid_bytes.len() == 2 {
                quote!(Uuid::Uuid16(u16::from_le_bytes([ #(#uuid_bytes),* ])))
            } else {
                quote!(Uuid::Uuid128([ #(#uuid_bytes),* ]))
            };

            decls.push(
                quote!(let #gen_attr_ident = Attribute::new(#gen_attr_att_uuid, &mut #gen_attr_att_data_ident);)
            );
            attribs.push(quote!(#gen_attr_ident));
            current_handle += 1;

            if characteristic.description.is_some() {
                let mut char_user_description_data: Vec<u8> = Vec::new();
                char_user_description_data
                    .extend(characteristic.description.as_ref().unwrap().bytes());
                let char_user_description_data_ident =
                    format_ident!("_char_user_description_data{}{}", i, j);
                decls.push(quote!(let #char_user_description_data_ident = [ #(#char_user_description_data),* ] ;));

                let char_user_description_data_attr =
                    format_ident!("_char_user_description_data_attr{}{}", i, j);
                decls.push(quote!(let mut #char_user_description_data_attr = &#char_user_description_data_ident;));

                let char_user_description_data_attribute =
                    format_ident!("_char_user_description_data_attribute{}{}", i, j);
                decls.push(
                    quote!(let #char_user_description_data_attribute = Attribute::new(Uuid::Uuid16(0x2901), &mut #char_user_description_data_attr);)
                );
                attribs.push(quote!(#char_user_description_data_attribute));
                current_handle += 1;
            }

            if characteristic.notify {
                let mut ccd_data: Vec<u8> = Vec::new();
                ccd_data.extend(&[0u8, 0u8]);
                let ccd_data_ident = format_ident!("_char_ccd_data{}{}", i, j);
                decls.push(quote!(let #ccd_data_ident = [ #(#ccd_data),* ] ;));

                let char_ccd_data_attr = format_ident!("_char_ccd_data_attr{}{}", i, j);
                let rfunction = format_ident!("_attr_read{}", current_handle);
                let wfunction = format_ident!("_attr_write{}", current_handle);
                decls.push(
                    quote!(let mut #char_ccd_data_attr = (&mut #rfunction, &mut #wfunction);),
                );

                let backing_data = format_ident!("_attr_data{}", current_handle);
                pre.push(quote!(
                    #[allow(non_upper_case_globals)]
                    static mut #backing_data: [u8; 2] = [0u8; 2];

                    let mut #rfunction = |offset: usize, data: &mut [u8]| {
                        let off = offset as usize;
                        unsafe {
                            if off < #backing_data.len() {
                                let len = #backing_data.len() - off;
                                if len > 0 {
                                    let len = len.min(data.len());
                                    data[..len].copy_from_slice(&#backing_data[off..off+len]);
                                    return len;
                                }
                            }
                        }
                        0
                    };
                    let mut #wfunction = |offset: usize, data: &[u8]| {
                        let off = offset as usize;
                        unsafe {
                            if off < #backing_data.len() {
                                let len = #backing_data.len() - off;
                                if len > 0 {
                                    let len = len.min(data.len());
                                    #backing_data[off..off+len].copy_from_slice(&data[..len]);
                                }
                            }
                        }
                    };
                ));

                let char_ccd_data_attribute = format_ident!("_char_ccd_data_attribute{}{}", i, j);
                decls.push(
                    quote!(let #char_ccd_data_attribute = Attribute::new(Uuid::Uuid16(0x2902), &mut #char_ccd_data_attr);)
                );
                attribs.push(quote!(#char_ccd_data_attribute));
                current_handle += 1;
            }

            if let Some(name) = &characteristic.name {
                let char_data_handle = (current_handle
                    - if characteristic.notify { 1 } else { 0 }
                    - if characteristic.description.is_some() {
                        1
                    } else {
                        0
                    }) as u16;

                let char_handle_name = format_ident!("{}_handle", name);
                post.push(quote!(let #char_handle_name = #char_data_handle;));

                if characteristic.notify {
                    let char_notify_enable_handle_name =
                        format_ident!("{}_notify_enable_handle", name);
                    let handle = char_data_handle
                        + if characteristic.description.is_some() {
                            1
                        } else {
                            0
                        };
                    post.push(quote!(let #char_notify_enable_handle_name = #handle;));
                }
            }
        }
    }

    let code = quote! {
        use bleps::Data;
        use bleps::att::Uuid;
        use bleps::attribute::Attribute;
        use bleps::attribute_server::CHARACTERISTIC_UUID16;
        use bleps::attribute_server::PRIMARY_SERVICE_UUID16;

        #(#pre)*
        #(#decls)*
        let mut gatt_attributes = [ #(#attribs),* ];

        #(#post)*
    };

    code.into()
}

fn path_to_string(path: Path) -> String {
    let mut res = String::new();
    for seg in path.segments {
        res.push_str(&seg.ident.to_string());
    }
    res
}

fn uuid_to_bytes(uuid: &str) -> Vec<u8> {
    if uuid.len() == 4 {
        let bytes = u16::to_le_bytes(u16::from_str_radix(&uuid, 16).unwrap());
        let mut res = Vec::new();
        res.extend(bytes);
        res
    } else {
        let uuid = uuid::Uuid::parse_str(&uuid).unwrap();
        let mut uuid_bytes = uuid.as_bytes().to_vec();
        uuid_bytes.reverse();
        uuid_bytes
    }
}

#[derive(Debug, Default)]
struct Service {
    uuid: String,
    characteristics: Vec<Characteristic>,
}

#[derive(Debug, Default)]
struct Characteristic {
    uuid: String,
    data: Option<String>,
    value: Option<String>,
    read: Option<String>,
    write: Option<String>,
    description: Option<String>,
    notify: bool,
    name: Option<String>,
}
