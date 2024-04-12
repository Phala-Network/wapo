use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use pink_types::js::JsValue;
use scale::Decode;
use tracing::{error, info};
use wapo_host::{wasmtime::Config, OutgoingRequest, WasmEngine, WasmInstanceConfig};

/// The compiler backend to use
#[derive(ValueEnum, Clone, Debug)]
enum Compiler {
    Auto,
    Cranelift,
    Winch,
}

impl From<Compiler> for wapo_host::wasmtime::Strategy {
    fn from(compiler: Compiler) -> Self {
        match compiler {
            Compiler::Auto => Self::Auto,
            Compiler::Cranelift => Self::Cranelift,
            Compiler::Winch => Self::Winch,
        }
    }
}

#[derive(Parser, Debug)]
#[clap(about = "wapo runner", version, author)]
pub struct Args {
    /// Max memory pages
    #[arg(long, default_value_t = 256)]
    max_memory_pages: u32,
    /// Decode the Output as JsValue
    #[arg(long, short = 'j')]
    decode_js_value: bool,
    /// The compiler to use
    #[arg(long, short = 'c', default_value = "winch")]
    compiler: Compiler,
    /// The WASM program to run
    program: String,
    /// The rest of the arguments are passed to the WASM program
    #[arg(last = true, trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
    args: Vec<String>,
}

pub async fn run(mut args: Args) -> Result<Vec<u8>> {
    let code = tokio::fs::read(&args.program).await?;
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(1);
    let config = WasmInstanceConfig {
        max_memory_pages: args.max_memory_pages,
        scheduler: None,
        weight: 0,
        id: Default::default(),
        event_tx,
        log_handler: None,
    };
    let mut engine_config = Config::new();
    engine_config.strategy(args.compiler.into());
    let engine = WasmEngine::new(&engine_config);
    let t0 = std::time::Instant::now();
    info!(target: "wapo", "Compiling wasm module");
    let module = engine.compile(&code)?;
    info!(target: "wapo", "Compiled wasm module in {:?}", t0.elapsed());
    args.args.insert(0, args.program);
    let vm_args = args
        .args
        .into_iter()
        .map(|s| -> Result<String> {
            if s.starts_with('@') {
                let path = &s[1..];
                let content = std::fs::read_to_string(path).context("Failed to read file")?;
                Ok(content)
            } else {
                Ok(s)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut wasm_run = module
        .run(vm_args, config)
        .context("Failed to start the instance")?;
    let mut output = None;
    tokio::select! {
        rv = &mut wasm_run => {
            if let Err(err) = rv {
                error!(target: "wapo", ?err, "Js runtime exited with error.");
            }
        }
        _ = async {
            while let Some((_vmid, event)) = event_rx.recv().await {
                match event {
                    OutgoingRequest::Output(output_bytes) => {
                        output = Some(output_bytes);
                        break;
                    }
                }
            }
        } => {}
    }
    if output.is_none() {
        while let Ok((_vmid, event)) = event_rx.try_recv() {
            match event {
                OutgoingRequest::Output(output_bytes) => {
                    output = Some(output_bytes);
                    break;
                }
            }
        }
    }
    Ok(output.unwrap_or_default())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let decode_output_js = args.decode_js_value;
    let output = run(args).await?;
    if decode_output_js {
        let js_value = JsValue::decode(&mut &output[..]).context("Failed to decode JsValue")?;
        println!("Output: {:?}", js_value);
    } else {
        println!("Output: {:?}", output);
    }
    Ok(())
}
