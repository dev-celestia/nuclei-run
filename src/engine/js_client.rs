//! JavaScript protocol engine backed by the `boa_engine` ECMAScript runtime.
//!
//! Mirrors nuclei's `pkg/protocols/javascript` runtime for the subset used by
//! nuclei templates:
//! - global helpers: `log`, `console.log`, `atob`, `btoa`, `isPortOpen`,
//!   `isUDPPortOpen`, `isTCPPortOpen`;
//! - `require("nuclei/net")` → `Open`, with connection methods `Close`,
//!   `SetTimeout`, `Send`, `SendHex`, `Recv`, `RecvString`;
//! - `require("nuclei/bytes")` → `Buffer` constructor with `Write`,
//!   `WriteString`, `Bytes`, `String`, `Len`, `Hex`.
//!
//! Template args (plus `Host`/`Port`) are injected as globals, the optional
//! `pre-condition` is evaluated first (falsy → block skipped), and the script's
//! completion value is used as the response for matching.

use boa_engine::object::builtins::JsArray;
use boa_engine::object::FunctionObjectBuilder;
use boa_engine::{Context, JsArgs, JsError, JsNativeError, JsObject, JsResult, JsString, JsValue, NativeFunction, Source};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use crate::models::template::JavaScriptBlock;

/// Result of running a javascript block.
#[derive(Debug, Clone)]
pub struct JavaScriptResponse {
    /// The script completion value, used as the matcher response body.
    pub output: String,
    /// False when the block's `pre-condition` was falsy and execution was skipped.
    pub precondition_met: bool,
}

// State for one synchronous JS execution. Runs on a blocking thread, so std
// blocking sockets are used directly.
thread_local! {
    static NET_CONNS: RefCell<HashMap<u64, Conn>> = RefCell::new(HashMap::new());
    static NET_CONN_ID: Cell<u64> = Cell::new(0);
    static BYTE_BUFFERS: RefCell<HashMap<u64, Vec<u8>>> = RefCell::new(HashMap::new());
    static BUFFER_ID: Cell<u64> = Cell::new(0);
}

enum Conn {
    Tcp(TcpStream),
    Udp(UdpSocket),
}

impl Conn {
    fn set_timeout(&self, secs: u64) {
        let d = Some(Duration::from_secs(secs.max(1)));
        match self {
            Conn::Tcp(s) => {
                let _ = s.set_read_timeout(d);
                let _ = s.set_write_timeout(d);
            }
            Conn::Udp(s) => {
                let _ = s.set_read_timeout(d);
                let _ = s.set_write_timeout(d);
            }
        }
    }

    fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            Conn::Tcp(s) => s.write_all(data),
            Conn::Udp(s) => s.send(data).map(|_| ()),
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Conn::Tcp(s) => s.read(buf),
            Conn::Udp(s) => s.recv(buf),
        }
    }
}

pub struct JavaScriptClient;

impl JavaScriptClient {
    /// Execute a javascript block against a target URL.
    pub async fn execute(
        block: &JavaScriptBlock,
        target: &str,
    ) -> Result<JavaScriptResponse, String> {
        let code = block.code.clone().unwrap_or_default();
        let pre_condition = block.pre_condition.clone();
        let args = block.args.clone();
        let target = target.to_string();

        tokio::task::spawn_blocking(move || {
            run_js(&code, pre_condition.as_deref(), &target, &args)
        })
        .await
        .map_err(|e| e.to_string())?
    }
}

/// Run the JS block synchronously on the current (blocking) thread.
fn run_js(
    code: &str,
    pre_condition: Option<&str>,
    target: &str,
    args: &HashMap<String, String>,
) -> Result<JavaScriptResponse, String> {
    let (host, port) = split_target(target);

    let mut context = Context::default();

    // Inject Host / Port and template args as globals.
    context
        .register_global_property(
            JsString::from("Host"),
            JsValue::from(JsString::from(host.as_str())),
            boa_engine::property::Attribute::all(),
        )
        .map_err(|e| e.to_string())?;
    context
        .register_global_property(
            JsString::from("Port"),
            JsValue::from(JsString::from(port.as_str())),
            boa_engine::property::Attribute::all(),
        )
        .map_err(|e| e.to_string())?;
    for (k, v) in args {
        context
            .register_global_property(
                JsString::from(k.as_str()),
                JsValue::from(JsString::from(v.as_str())),
                boa_engine::property::Attribute::all(),
            )
            .map_err(|e| e.to_string())?;
    }

    register_helpers(&mut context)?;

    // require("nuclei/net" | "nuclei/bytes")
    let require = NativeFunction::from_copy_closure(
        |_this: &JsValue, args: &[JsValue], context: &mut Context| -> JsResult<JsValue> {
            let module = args
                .get_or_undefined(0)
                .to_string(context)?
                .to_std_string_escaped();
            match module.as_str() {
                "nuclei/net" => Ok(JsValue::from(net_module(context))),
                "nuclei/bytes" => Ok(JsValue::from(bytes_module(context))),
                other => Err(JsError::from_native(
                    JsNativeError::typ().with_message(format!("unknown module: {}", other)),
                )),
            }
        },
    );
    context
        .register_global_callable(JsString::from("require"), 1, require)
        .map_err(|e| e.to_string())?;

    // Evaluate pre-condition; a falsy result skips the block.
    if let Some(pc) = pre_condition {
        let result = context
            .eval(Source::from_bytes(pc.as_bytes()))
            .map_err(|e| format!("pre-condition error: {}", e))?;
        if !truthy(&result) {
            return Ok(JavaScriptResponse {
                output: String::new(),
                precondition_met: false,
            });
        }
    }

    let result = context
        .eval(Source::from_bytes(code.as_bytes()))
        .map_err(|e| format!("JS execution error: {}", e))?;
    let output = result
        .to_string(&mut context)
        .map(|s| s.to_std_string_escaped())
        .unwrap_or_default();

    Ok(JavaScriptResponse {
        output,
        precondition_met: true,
    })
}

/// Split a target URL into (host, port) strings for the JS runtime globals.
fn split_target(target: &str) -> (String, String) {
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
fn truthy(value: &JsValue) -> bool {
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

/// Register global helper functions.
fn register_helpers(context: &mut Context) -> Result<(), String> {
    let log = NativeFunction::from_copy_closure(
        |_this: &JsValue, args: &[JsValue], context: &mut Context| -> JsResult<JsValue> {
            let v = args.get_or_undefined(0);
            let msg = v
                .to_string(context)
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_default();
            eprintln!("[JS] {}", msg);
            Ok(v.clone())
        },
    );
    context
        .register_global_callable(JsString::from("log"), 1, log.clone())
        .map_err(|e| e.to_string())?;
    context
        .register_global_callable(JsString::from("console.log"), 1, log)
        .map_err(|e| e.to_string())?;

    let atob = NativeFunction::from_copy_closure(
        |_this: &JsValue, args: &[JsValue], context: &mut Context| -> JsResult<JsValue> {
            let s = args
                .get_or_undefined(0)
                .to_string(context)?
                .to_std_string_escaped();
            use base64::{engine::general_purpose, Engine as _};
            match general_purpose::STANDARD.decode(s) {
                Ok(bytes) => {
                    let decoded = String::from_utf8_lossy(&bytes).to_string();
                    Ok(JsValue::from(JsString::from(decoded.as_str())))
                }
                Err(_) => Ok(JsValue::null()),
            }
        },
    );
    let btoa = NativeFunction::from_copy_closure(
        |_this: &JsValue, args: &[JsValue], context: &mut Context| -> JsResult<JsValue> {
            let s = args
                .get_or_undefined(0)
                .to_string(context)?
                .to_std_string_escaped();
            use base64::{engine::general_purpose, Engine as _};
            let encoded = general_purpose::STANDARD.encode(s.as_bytes());
            Ok(JsValue::from(JsString::from(encoded.as_str())))
        },
    );
    context
        .register_global_callable(JsString::from("atob"), 1, atob)
        .map_err(|e| e.to_string())?;
    context
        .register_global_callable(JsString::from("btoa"), 1, btoa)
        .map_err(|e| e.to_string())?;

    let is_tcp_open = NativeFunction::from_copy_closure(
        |_this: &JsValue, args: &[JsValue], context: &mut Context| -> JsResult<JsValue> {
            let host = arg_string(args, 0, context);
            let port = arg_string(args, 1, context);
            let timeout = arg_u64(args, 2, context).unwrap_or(5).max(1);
            let addr = format!("{}:{}", host, port);
            let open = addr
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
                .and_then(|a| TcpStream::connect_timeout(&a, Duration::from_secs(timeout)).ok())
                .is_some();
            Ok(JsValue::from(open))
        },
    );
    context
        .register_global_callable(JsString::from("isPortOpen"), 3, is_tcp_open.clone())
        .map_err(|e| e.to_string())?;
    context
        .register_global_callable(JsString::from("isTCPPortOpen"), 3, is_tcp_open)
        .map_err(|e| e.to_string())?;

    let is_udp_open = NativeFunction::from_copy_closure(
        |_this: &JsValue, args: &[JsValue], context: &mut Context| -> JsResult<JsValue> {
            let host = arg_string(args, 0, context);
            let port = arg_string(args, 1, context);
            let open = UdpSocket::bind("0.0.0.0:0")
                .and_then(|s| s.connect(format!("{}:{}", host, port)).map(|_| s))
                .is_ok();
            Ok(JsValue::from(open))
        },
    );
    context
        .register_global_callable(JsString::from("isUDPPortOpen"), 2, is_udp_open)
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// `require("nuclei/net")` module object.
fn net_module(context: &mut Context) -> JsObject {
    let open = NativeFunction::from_copy_closure(
        |_this: &JsValue, args: &[JsValue], context: &mut Context| -> JsResult<JsValue> {
            let protocol = arg_string(args, 0, context);
            let address = arg_string(args, 1, context);
            let timeout = arg_u64(args, 2, context).unwrap_or(5).max(1);

            let conn = match protocol.to_lowercase().as_str() {
                "tcp" => {
                    let addr = address
                        .to_socket_addrs()
                        .map_err(|e| JsError::from_native(JsNativeError::typ().with_message(e.to_string())))?
                        .next()
                        .ok_or_else(|| JsError::from_native(JsNativeError::typ().with_message("no address resolved")))?;
                    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(timeout))
                        .map_err(|e| JsError::from_native(JsNativeError::typ().with_message(e.to_string())))?;
                    Conn::Tcp(stream)
                }
                "udp" => {
                    let socket = UdpSocket::bind("0.0.0.0:0")
                        .map_err(|e| JsError::from_native(JsNativeError::typ().with_message(e.to_string())))?;
                    socket
                        .connect(&address)
                        .map_err(|e| JsError::from_native(JsNativeError::typ().with_message(e.to_string())))?;
                    Conn::Udp(socket)
                }
                other => {
                    return Err(JsError::from_native(
                        JsNativeError::typ().with_message(format!("unsupported protocol: {}", other)),
                    ))
                }
            };

            let id = NET_CONN_ID.with(|c| {
                let id = c.get();
                c.set(id + 1);
                id
            });
            NET_CONNS.with(|m| {
                m.borrow_mut().insert(id, conn);
            });

            Ok(make_conn_object(id, context))
        },
    );

    let obj = JsObject::default(context.intrinsics());
    let _ = obj.set(JsString::from("Open"), js_function(context, open), false, context);
    obj
}

/// Build a JS object exposing the NetConn methods for a connection id.
fn make_conn_object(id: u64, context: &mut Context) -> JsValue {
    let close = NativeFunction::from_copy_closure(
        move |_this: &JsValue, _args: &[JsValue], _context: &mut Context| -> JsResult<JsValue> {
            NET_CONNS.with(|m| {
                m.borrow_mut().remove(&id);
            });
            Ok(JsValue::null())
        },
    );
    let set_timeout = NativeFunction::from_copy_closure(
        move |_this: &JsValue, args: &[JsValue], context: &mut Context| -> JsResult<JsValue> {
            let secs = arg_u64(args, 0, context).unwrap_or(5);
            NET_CONNS.with(|m| {
                if let Some(c) = m.borrow().get(&id) {
                    c.set_timeout(secs);
                }
            });
            Ok(JsValue::undefined())
        },
    );
    let send = NativeFunction::from_copy_closure(
        move |_this: &JsValue, args: &[JsValue], context: &mut Context| -> JsResult<JsValue> {
            let data = args
                .get_or_undefined(0)
                .to_string(context)?
                .to_std_string_escaped()
                .into_bytes();
            let mut result = false;
            NET_CONNS.with(|m| {
                if let Some(c) = m.borrow_mut().get_mut(&id) {
                    result = c.send(&data).is_ok();
                }
            });
            Ok(JsValue::from(result))
        },
    );
    let send_hex = NativeFunction::from_copy_closure(
        move |_this: &JsValue, args: &[JsValue], context: &mut Context| -> JsResult<JsValue> {
            let hex_str = args
                .get_or_undefined(0)
                .to_string(context)?
                .to_std_string_escaped();
            let data = hex::decode(hex_str.trim())
                .map_err(|e| JsError::from_native(JsNativeError::typ().with_message(e.to_string())))?;
            let mut result = false;
            NET_CONNS.with(|m| {
                if let Some(c) = m.borrow_mut().get_mut(&id) {
                    result = c.send(&data).is_ok();
                }
            });
            Ok(JsValue::from(result))
        },
    );
    let recv = NativeFunction::from_copy_closure(
        move |_this: &JsValue, args: &[JsValue], context: &mut Context| -> JsResult<JsValue> {
            let n = arg_u64(args, 0, context).unwrap_or(4096).clamp(1, 1 << 24) as usize;
            let mut buf = vec![0u8; n];
            let got = NET_CONNS.with(|m| match m.borrow_mut().get_mut(&id) {
                Some(c) => c.recv(&mut buf).ok(),
                None => None,
            });
            match got {
                Some(read) if read > 0 => Ok(js_bytes(&buf[..read], context)),
                _ => Ok(JsValue::null()),
            }
        },
    );
    let recv_string = NativeFunction::from_copy_closure(
        move |_this: &JsValue, args: &[JsValue], context: &mut Context| -> JsResult<JsValue> {
            let n = arg_u64(args, 0, context).unwrap_or(4096).clamp(1, 1 << 24) as usize;
            let mut buf = vec![0u8; n];
            let got = NET_CONNS.with(|m| match m.borrow_mut().get_mut(&id) {
                Some(c) => c.recv(&mut buf).ok(),
                None => None,
            });
            match got {
                Some(read) if read > 0 => {
                    let s = String::from_utf8_lossy(&buf[..read]).to_string();
                    Ok(JsValue::from(JsString::from(s.as_str())))
                }
                _ => Ok(JsValue::null()),
            }
        },
    );

    let obj = JsObject::default(context.intrinsics());
    let _ = obj.set(JsString::from("Close"), js_function(context, close), false, context);
    let _ = obj.set(JsString::from("SetTimeout"), js_function(context, set_timeout), false, context);
    let _ = obj.set(JsString::from("Send"), js_function(context, send), false, context);
    let _ = obj.set(JsString::from("SendHex"), js_function(context, send_hex), false, context);
    let _ = obj.set(JsString::from("Recv"), js_function(context, recv), false, context);
    let _ = obj.set(JsString::from("RecvString"), js_function(context, recv_string), false, context);
    JsValue::from(obj)
}

/// `require("nuclei/bytes")` module object (with a Buffer constructor).
fn bytes_module(context: &mut Context) -> JsObject {
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

    let obj = JsObject::default(context.intrinsics());
    let _ = obj.set(JsString::from("Buffer"), js_function(context, buffer_ctor), false, context);
    obj
}

fn buffer_write_fn(id: u64) -> NativeFunction {
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

fn buffer_write_string_fn(id: u64) -> NativeFunction {
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

fn buffer_bytes_fn(id: u64) -> NativeFunction {
    NativeFunction::from_copy_closure(
        move |_this: &JsValue, _args: &[JsValue], context: &mut Context| -> JsResult<JsValue> {
            let bytes = BYTE_BUFFERS.with(|m| m.borrow().get(&id).cloned().unwrap_or_default());
            Ok(js_bytes(&bytes, context))
        },
    )
}

fn buffer_string_fn(id: u64) -> NativeFunction {
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

fn buffer_len_fn(id: u64) -> NativeFunction {
    NativeFunction::from_copy_closure(
        move |_this: &JsValue, _args: &[JsValue], _context: &mut Context| -> JsResult<JsValue> {
            let n = BYTE_BUFFERS.with(|m| m.borrow().get(&id).map(|b| b.len()).unwrap_or(0));
            Ok(JsValue::from(n as i32))
        },
    )
}

fn buffer_hex_fn(id: u64) -> NativeFunction {
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

/// Build a JS function value from a native function.
fn js_function(context: &mut Context, f: NativeFunction) -> JsValue {
    let func = FunctionObjectBuilder::new(context.realm(), f)
        .constructor(true)
        .build();
    JsValue::from(func)
}

/// Build a JS array of integers from a byte slice.
fn js_bytes(bytes: &[u8], context: &mut Context) -> JsValue {
    let arr = JsArray::from_iter(
        bytes.iter().map(|b| JsValue::from(i32::from(*b))),
        context,
    );
    JsValue::from(arr)
}

/// Convert a JS string / array / typed array into bytes.
fn value_to_bytes(value: &JsValue, context: &mut Context) -> Option<Vec<u8>> {
    if let Some(s) = value.as_string() {
        return Some(s.to_std_string_escaped().into_bytes());
    }
    let obj = value.as_object()?;
    let len = obj
        .get(JsString::from("length"), context)
        .ok()?
        .to_number(context)
        .ok()? as usize;
    let mut out = Vec::with_capacity(len.min(1 << 20));
    for i in 0..len {
        let item = obj.get(i as u32, context).ok()?;
        let byte = item.to_number(context).ok()? as u8;
        out.push(byte);
    }
    Some(out)
}

fn arg_string(args: &[JsValue], idx: usize, context: &mut Context) -> String {
    args.get(idx)
        .and_then(|v| v.to_string(context).ok())
        .map(|s| s.to_std_string_escaped())
        .unwrap_or_default()
}

fn arg_u64(args: &[JsValue], idx: usize, context: &mut Context) -> Option<u64> {
    args.get(idx)
        .and_then(|v| v.to_number(context).ok())
        .map(|n| n.max(0.0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(code: &str) -> JavaScriptBlock {
        JavaScriptBlock {
            code: Some(code.to_string()),
            pre_condition: None,
            args: HashMap::new(),
            matchers_condition: None,
            matchers: vec![],
            extractors: vec![],
        }
    }

    #[tokio::test]
    async fn test_simple_expression() {
        let b = block("40 + 2");
        let res = JavaScriptClient::execute(&b, "https://example.com").await.unwrap();
        assert!(res.precondition_met);
        assert_eq!(res.output, "42");
    }

    #[tokio::test]
    async fn test_arg_injection() {
        let mut b = block("serobj.length");
        b.args.insert("serobj".to_string(), "hello".to_string());
        let res = JavaScriptClient::execute(&b, "https://example.com").await.unwrap();
        assert_eq!(res.output, "5");
    }

    #[tokio::test]
    async fn test_precondition_falsy_skips() {
        let mut b = block("1 + 1");
        b.pre_condition = Some("false".to_string());
        let res = JavaScriptClient::execute(&b, "https://example.com").await.unwrap();
        assert!(!res.precondition_met);
        assert!(res.output.is_empty());
    }

    #[tokio::test]
    async fn test_bytes_buffer_roundtrip() {
        let b = block(
            r#"
            const bytess = require("nuclei/bytes");
            var buf = new bytess.Buffer();
            buf.Write([104, 101, 108, 108, 111]);
            buf.Hex()
            "#,
        );
        let res = JavaScriptClient::execute(&b, "https://example.com").await.unwrap();
        assert_eq!(res.output, "68656c6c6f");
    }

    #[tokio::test]
    async fn test_bigint_and_typed_array() {
        let b = block(
            r#"
            const x = BigInt("0xdeadbeef");
            const arr = new Uint8Array([1, 2, 3, 4]);
            (x + BigInt(1)).toString(16) + ":" + arr.length
            "#,
        );
        let res = JavaScriptClient::execute(&b, "https://example.com").await.unwrap();
        assert_eq!(res.output, "deadbef0:4");
    }

    #[test]
    fn test_split_target() {
        assert_eq!(
            split_target("https://example.com:8443/path"),
            ("example.com".to_string(), "8443".to_string())
        );
        assert_eq!(
            split_target("http://example.com"),
            ("example.com".to_string(), "80".to_string())
        );
    }

    #[test]
    fn test_truthy() {
        assert!(!truthy(&JsValue::null()));
        assert!(!truthy(&JsValue::undefined()));
        assert!(!truthy(&JsValue::from(false)));
        assert!(truthy(&JsValue::from(true)));
        assert!(truthy(&JsValue::from(42)));
        assert!(!truthy(&JsValue::from(0)));
        assert!(truthy(&JsValue::from(JsString::from("x"))));
        assert!(!truthy(&JsValue::from(JsString::from(""))));
    }
}
