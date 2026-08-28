use crate::engine::js_client::conversions::{arg_string, arg_u64, js_bytes, js_function};
use boa_engine::{Context, JsArgs, JsError, JsNativeError, JsObject, JsResult, JsString, JsValue, NativeFunction};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

thread_local! {
    pub static NET_CONNS: RefCell<HashMap<u64, Conn>> = RefCell::new(HashMap::new());
    pub static NET_CONN_ID: Cell<u64> = Cell::new(0);
}

pub enum Conn {
    Tcp(TcpStream),
    Udp(UdpSocket),
}

impl Conn {
    pub fn set_timeout(&self, secs: u64) {
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

    pub fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            Conn::Tcp(s) => s.write_all(data),
            Conn::Udp(s) => s.send(data).map(|_| ()),
        }
    }

    pub fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Conn::Tcp(s) => s.read(buf),
            Conn::Udp(s) => s.recv(buf),
        }
    }
}

/// `require("nuclei/net")` module object.
pub fn net_module(context: &mut Context) -> JsObject {
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
pub fn make_conn_object(id: u64, context: &mut Context) -> JsValue {
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
