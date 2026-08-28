use boa_engine::object::builtins::JsArray;
use boa_engine::object::FunctionObjectBuilder;
use boa_engine::{Context, JsArgs, JsValue, NativeFunction};

/// Split a target URL into (host, port) strings for the JS runtime globals.
pub fn split_target(target: &str) -> (String, String) {
    let with_scheme = if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        format!("https://{}", target)
    };
    match url::Url::parse(&with_scheme) {
        Ok(u) => {
            let host = u.host_str().unwrap_or("").to_string();
            let port = u
                .port_or_known_default()
                .map(|p| p.to_string())
                .unwrap_or_default();
            (host, port)
        }
        Err(_) => (target.trim_end_matches('/').to_string(), String::new()),
    }
}

/// Truthiness check matching ECMAScript `ToBoolean`.
pub fn truthy(value: &JsValue) -> bool {
    if value.is_null_or_undefined() {
        return false;
    }
    if let Some(b) = value.as_boolean() {
        return b;
    }
    if let Some(n) = value.as_number() {
        return n != 0.0 && !n.is_nan();
    }
    if let Some(s) = value.as_string() {
        return !s.is_empty();
    }
    true
}

pub fn js_function(context: &mut Context, f: NativeFunction) -> JsValue {
    FunctionObjectBuilder::new(context.realm(), f)
        .build()
        .into()
}

pub fn js_bytes(bytes: &[u8], context: &mut Context) -> JsValue {
    let arr = JsArray::new(context);
    for &b in bytes {
        let _ = arr.push(JsValue::from(b as i32), context);
    }
    arr.into()
}

pub fn value_to_bytes(value: &JsValue, context: &mut Context) -> Option<Vec<u8>> {
    if let Some(s) = value.as_string() {
        return Some(s.to_std_string_escaped().into_bytes());
    }
    if let Some(obj) = value.as_object() {
        if let Ok(arr) = JsArray::from_object(obj.clone()) {
            let len = arr.length(context).unwrap_or(0);
            let mut out = Vec::with_capacity(len as usize);
            for i in 0..len {
                if let Ok(item) = arr.get(i, context) {
                    let b = item.to_u32(context).unwrap_or(0) as u8;
                    out.push(b);
                }
            }
            return Some(out);
        }
    }
    None
}

pub fn arg_string(args: &[JsValue], idx: usize, context: &mut Context) -> String {
    args.get_or_undefined(idx)
        .to_string(context)
        .map(|s| s.to_std_string_escaped())
        .unwrap_or_default()
}

pub fn arg_u64(args: &[JsValue], idx: usize, context: &mut Context) -> Option<u64> {
    let v = args.get_or_undefined(idx);
    if let Some(i) = v.as_i32() {
        Some(i.max(0) as u64)
    } else {
        v.to_number(context).ok().map(|n| n.max(0.0) as u64)
    }
}
