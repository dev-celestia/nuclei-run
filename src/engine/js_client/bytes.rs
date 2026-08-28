use crate::engine::js_client::conversions::{js_bytes, js_function, value_to_bytes};
use boa_engine::object::FunctionObjectBuilder;
use boa_engine::{Context, JsArgs, JsObject, JsResult, JsString, JsValue, NativeFunction};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;

thread_local! {
    pub static BYTE_BUFFERS: RefCell<HashMap<u64, Vec<u8>>> = RefCell::new(HashMap::new());
    pub static BUFFER_ID: Cell<u64> = Cell::new(0);
}

/// `require("nuclei/bytes")` module object (with a Buffer constructor).
pub fn bytes_module(context: &mut Context) -> JsObject {
    let buffer_ctor = NativeFunction::from_copy_closure(
        |this: &JsValue, args: &[JsValue], context: &mut Context| -> JsResult<JsValue> {
            let mut initial: Vec<u8> = Vec::new();
            if let Some(arg) = args.get(0) {
                if !arg.is_undefined() {
                    initial = value_to_bytes(arg, context).unwrap_or_default();
                }
            }

            let id = BUFFER_ID.with(|c| {
                let id = c.get();
                c.set(id + 1);
                id
            });
            BYTE_BUFFERS.with(|m| {
                m.borrow_mut().insert(id, initial);
            });

            if let Some(obj) = this.as_object() {
                let _ = obj.set(JsString::from("Write"), js_function(context, buffer_write_fn(id)), false, context);
                let _ = obj.set(JsString::from("WriteString"), js_function(context, buffer_write_string_fn(id)), false, context);
                let _ = obj.set(JsString::from("Bytes"), js_function(context, buffer_bytes_fn(id)), false, context);
                let _ = obj.set(JsString::from("String"), js_function(context, buffer_string_fn(id)), false, context);
                let _ = obj.set(JsString::from("Len"), js_function(context, buffer_len_fn(id)), false, context);
                let _ = obj.set(JsString::from("Hex"), js_function(context, buffer_hex_fn(id)), false, context);
            }
            Ok(this.clone())
        },
    );

    let ctor_fn = FunctionObjectBuilder::new(context.realm(), buffer_ctor)
        .constructor(true)
        .build();

    let obj = JsObject::default(context.intrinsics());
    let _ = obj.set(JsString::from("Buffer"), ctor_fn, false, context);
    obj
}

pub fn buffer_write_fn(id: u64) -> NativeFunction {
    NativeFunction::from_copy_closure(
        move |_this: &JsValue, args: &[JsValue], context: &mut Context| -> JsResult<JsValue> {
            if let Some(arg) = args.get(0) {
                let bytes = value_to_bytes(arg, context).unwrap_or_default();
                BYTE_BUFFERS.with(|m| {
                    if let Some(buf) = m.borrow_mut().get_mut(&id) {
                        buf.extend_from_slice(&bytes);
                    }
                });
            }
            Ok(JsValue::undefined())
        },
    )
}

pub fn buffer_write_string_fn(id: u64) -> NativeFunction {
    NativeFunction::from_copy_closure(
        move |_this: &JsValue, args: &[JsValue], context: &mut Context| -> JsResult<JsValue> {
            let s = args
                .get_or_undefined(0)
                .to_string(context)?
                .to_std_string_escaped();
            BYTE_BUFFERS.with(|m| {
                if let Some(buf) = m.borrow_mut().get_mut(&id) {
                    buf.extend_from_slice(s.as_bytes());
                }
            });
            Ok(JsValue::undefined())
        },
    )
}

pub fn buffer_bytes_fn(id: u64) -> NativeFunction {
    NativeFunction::from_copy_closure(
        move |_this: &JsValue, _args: &[JsValue], context: &mut Context| -> JsResult<JsValue> {
            let bytes = BYTE_BUFFERS.with(|m| m.borrow().get(&id).cloned().unwrap_or_default());
            Ok(js_bytes(&bytes, context))
        },
    )
}

pub fn buffer_string_fn(id: u64) -> NativeFunction {
    NativeFunction::from_copy_closure(
        move |_this: &JsValue, _args: &[JsValue], _context: &mut Context| -> JsResult<JsValue> {
            let s = BYTE_BUFFERS.with(|m| {
                m.borrow()
                    .get(&id)
                    .map(|b| String::from_utf8_lossy(b).to_string())
                    .unwrap_or_default()
            });
            Ok(JsValue::from(JsString::from(s.as_str())))
        },
    )
}

pub fn buffer_len_fn(id: u64) -> NativeFunction {
    NativeFunction::from_copy_closure(
        move |_this: &JsValue, _args: &[JsValue], _context: &mut Context| -> JsResult<JsValue> {
            let n = BYTE_BUFFERS.with(|m| m.borrow().get(&id).map(|b| b.len()).unwrap_or(0));
            Ok(JsValue::from(n as i32))
        },
    )
}

pub fn buffer_hex_fn(id: u64) -> NativeFunction {
    NativeFunction::from_copy_closure(
        move |_this: &JsValue, _args: &[JsValue], _context: &mut Context| -> JsResult<JsValue> {
            let s = BYTE_BUFFERS.with(|m| {
                m.borrow()
                    .get(&id)
                    .map(|b| hex::encode(b))
                    .unwrap_or_default()
            });
            Ok(JsValue::from(JsString::from(s.as_str())))
        },
    )
}
