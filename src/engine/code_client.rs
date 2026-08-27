use crate::models::template::CodeBlock;
use std::process::Stdio;
use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct CodeResponse {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub raw: String,
}

pub struct CodeClient;

impl CodeClient {
    pub async fn execute(
        block: &CodeBlock,
        target: &str,
        enabled: bool,
    ) -> Result<CodeResponse, String> {
        if !enabled {
            return Err("Code template execution is disabled. Use --enable-code-templates to run.".to_string());
        }

        let engine = block.engine.as_deref().unwrap_or("sh");
        let source = block.source.as_deref().unwrap_or("");

        let mut cmd = match engine {
            "bash" => {
                let mut c = Command::new("bash");
                c.arg("-c").arg(source);
                c
            }
            "python3" | "py" | "python" => {
                let mut c = Command::new("python3");
                c.arg("-c").arg(source);
                c
            }
            "powershell" | "pwsh" => {
                let mut c = Command::new("powershell");
                c.arg("-Command").arg(source);
                c
            }
            "cmd" => {
                let mut c = Command::new("cmd");
                c.arg("/C").arg(source);
                c
            }
            _ => {
                let mut c = Command::new("sh");
                c.arg("-c").arg(source);
                c
            }
        };

        cmd.env("NUCLEI_TARGET", target);
        for arg in &block.args {
            cmd.arg(arg);
        }

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let output = cmd
            .output()
            .await
            .map_err(|e| format!("Failed to execute process ({}): {}", engine, e))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let exit_code = output.status.code().unwrap_or(-1);
        let raw = format!("{}\n{}", stdout, stderr);

        Ok(CodeResponse {
            stdout,
            stderr,
            exit_code,
            raw,
        })
    }
}
