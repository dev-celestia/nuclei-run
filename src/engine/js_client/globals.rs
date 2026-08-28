use crate::engine::js_client::conversions::{arg_string, arg_u64};
use boa_engine::{Context, JsArgs, JsResult, JsString, JsValue, NativeFunction};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// Register global helper functions.
pub fn register_helpers(context: &mut Context) -> Result<(), String> {
    let log = NativeFunction::from_copy_closure(
        |_this: &JsValue, args: &[JsValue], context: &mut Context| -> JsResult<JsValue> {
            let v = args.get_or_undefined(0);
            let msg = v
                .to_string(context)?
                .to_std_string_escaped();
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
