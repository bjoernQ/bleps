use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, Expr, Lit, Member, Path};

/// Creates an array named `gatt_attributes` defining the given services
///
/// ```no-execute
/// gatt!([
/// service {
///     uuid: "9e7312e0-2354-11eb-9f10-fbc30a62cf38",
///     characteristics: [
///         characteristic {
///              uuid: "9e7312e0-2354-11eb-9f10-fbc30a62cf38",
///              read: my_read_function,
///              write: my_write_function,
///         },
///     ],
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

                let mut service = Service {
                    uuid: String::new(),
                    characteristics: Vec::new(),
                };

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

                                        let mut charact = Characteristic {
                                            uuid: String::new(),
                                            read: None,
                                            write: None,
                                            description: None,
                                        };

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
    for (i, service) in services.iter().enumerate() {
        let uuid_bytes = uuid_to_bytes(&service.uuid);
        let uuid_ident = format_ident!("_uuid{}", i);

        decls.push(quote!(let #uuid_ident = [ #(#uuid_bytes),* ] ;));

        let uuid_data = format_ident!("_uuid_data{}", i);
        decls.push(quote!(let mut #uuid_data = AttData::Static(&#uuid_ident);));

        let primary_service_ident = format_ident!("_primary_srv{}", i);
        decls.push(
            quote!(let #primary_service_ident = Attribute::new(PRIMARY_SERVICE_UUID16, &mut #uuid_data);)
        );

        attribs.push(quote!(#primary_service_ident));

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
                },
            );

            let char_handle = (attribs.len() + 1 + 1) as u16;
            char_data.extend(char_handle.to_le_bytes());
            let uuid_bytes = uuid_to_bytes(&characteristic.uuid);
            char_data.extend(uuid_bytes.clone());
            let char_data_ident = format_ident!("_char_data{}{}", i, j);
            decls.push(quote!(let #char_data_ident = [ #(#char_data),* ] ;));

            let char_data_attr = format_ident!("_char_data_attr{}{}", i, j);
            decls.push(quote!(let mut #char_data_attr = AttData::Static(&#char_data_ident);));

            let char_data_attribute = format_ident!("_char_data_attribute{}{}", i, j);
            decls.push(
                quote!(let #char_data_attribute = Attribute::new(CHARACTERISTIC_UUID16, &mut #char_data_attr);)
            );
            attribs.push(quote!(#char_data_attribute));

            let gen_attr_att_data_ident = format_ident!("_gen_attr_att_data{}{}", i, j);

            let rfunction = if characteristic.read.is_none() {
                quote!(None)
            } else {
                let fname = format_ident!("{}", characteristic.read.as_ref().unwrap());
                quote!(Some(&mut #fname))
            };
            let wfunction = if characteristic.write.is_none() {
                quote!(None)
            } else {
                let fname = format_ident!("{}", characteristic.write.as_ref().unwrap());
                quote!(Some(&mut #fname))
            };

            decls.push(
                quote!(let mut #gen_attr_att_data_ident = AttData::Dynamic { read_function: #rfunction, write_function: #wfunction};)
            );

            let gen_attr_ident = format_ident!("_gen_attr{}{}", i, j);
            if uuid_bytes.len() == 2 {
                decls.push(
                    quote!(let #gen_attr_ident = Attribute::new(Uuid::Uuid16( u16::from_le_bytes([ #(#uuid_bytes),* ])), &mut #gen_attr_att_data_ident);)
                );
            } else {
                decls.push(
                    quote!(let #gen_attr_ident = Attribute::new(Uuid::Uuid128([ #(#uuid_bytes),* ]), &mut #gen_attr_att_data_ident);)
                );
            }
            attribs.push(quote!(#gen_attr_ident));

            if characteristic.description.is_some() {
                let mut char_user_description_data: Vec<u8> = Vec::new();
                char_user_description_data
                    .extend(characteristic.description.as_ref().unwrap().bytes());
                let char_user_description_data_ident =
                    format_ident!("_char_user_description_data{}{}", i, j);
                decls.push(quote!(let #char_user_description_data_ident = [ #(#char_user_description_data),* ] ;));

                let char_user_description_data_attr =
                    format_ident!("_char_user_description_data_attr{}{}", i, j);
                decls.push(quote!(let mut #char_user_description_data_attr = AttData::Static(&#char_user_description_data_ident);));

                let char_user_description_data_attribute =
                    format_ident!("_char_user_description_data_attribute{}{}", i, j);
                decls.push(
                    quote!(let #char_user_description_data_attribute = Attribute::new(Uuid::Uuid16(0x2901), &mut #char_user_description_data_attr);)
                );
                attribs.push(quote!(#char_user_description_data_attribute));
            }
        }
    }

    let code = quote! {
        use bleps::Data;
        use bleps::att::Uuid;
        use bleps::attribute_server::AttData;
        use bleps::attribute_server::Attribute;
        use bleps::attribute_server::CHARACTERISTIC_UUID16;
        use bleps::attribute_server::PRIMARY_SERVICE_UUID16;

        #(#decls)*
        let mut gatt_attributes = [ #(#attribs),* ];
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

#[derive(Debug)]
struct Service {
    uuid: String,
    characteristics: Vec<Characteristic>,
}

#[derive(Debug)]
struct Characteristic {
    uuid: String,
    read: Option<String>,
    write: Option<String>,
    description: Option<String>,
}
