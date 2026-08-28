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

pub mod bytes;
pub mod conversions;
pub mod globals;
pub mod net;

pub use conversions::{split_target, truthy};

use crate::models::template::JavaScriptBlock;
use boa_engine::{Context, JsError, JsNativeError, JsResult, JsString, JsValue, NativeFunction, Source};
use std::collections::HashMap;

/// Result of running a javascript block.
#[derive(Debug, Clone)]
pub struct JavaScriptResponse {
    /// The script completion value, used as the matcher response body.
    pub output: String,
    /// False when the block's `pre-condition` was falsy and execution was skipped.
    pub precondition_met: bool,
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
pub fn run_js(
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

    globals::register_helpers(&mut context)?;

    // require("nuclei/net" | "nuclei/bytes")
    let require = NativeFunction::from_copy_closure(
        |_this: &JsValue, args: &[JsValue], context: &mut Context| -> JsResult<JsValue> {
            let module = conversions::arg_string(args, 0, context);
            match module.as_str() {
                "nuclei/net" => Ok(JsValue::from(net::net_module(context))),
                "nuclei/bytes" => Ok(JsValue::from(bytes::bytes_module(context))),
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
