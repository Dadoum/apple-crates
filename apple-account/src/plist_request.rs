use plist::{Dictionary, Value};
use reqwest::Body;

pub fn plist_to_body(val: Value) -> Body {
    // UNWRAP safety: I don't know any reason why the serializer should fail.
    // If it happens, I would guess it's a serious flaw in the plist crate.
    let mut request_body = Vec::new();
    plist::to_writer_xml(&mut request_body, &val).expect("Failed to serialize plist?");

    Body::from(request_body)
}

pub fn dict_to_body(dict: Dictionary) -> Body {
    plist_to_body(Value::Dictionary(dict))
}
