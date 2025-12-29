#[macro_export]
macro_rules! dict {
    {
        $($key:literal : $value:expr),* $(,)?
    } => {{
        let mut dict = plist::Dictionary::new();
        $(
            dict.insert(
                $key.to_string(),
                plist::Value::from($value),
            );
        )*
        dict
    }};
}

#[macro_export]
macro_rules! array {
    [
        $($value:expr),* $(,)?
    ] => {{
        vec![
            $(plist::Value::from($value),)*
        ]
    }};
}
