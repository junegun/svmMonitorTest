// transaction_monitor/src/main.rs

use {
    solana_sdk::{
        transaction::Transaction,
        message::Message,
        instruction::CompiledInstruction,
    },
    std::{
        time::{SystemTime, UNIX_EPOCH, Duration},
        env,
        process,
        thread,
        sync::{Arc, Mutex},
    },
    quinn::{Endpoint, ServerConfig, TransportConfig},
    tokio::runtime::Runtime,
};

const BUFFER_SIZE: usize = 5232; // Solana max transaction size
const RETRY_DELAY: Duration = Duration::from_secs(5);

struct TransactionMonitor {
    host: String,
    port: u16,
    endpoint: Option<Endpoint>,
}

impl TransactionMonitor {
    fn new(host: String, port: u16) -> Self {
        Self { 
            host,
            port,
            endpoint: None,
        }
    }

    fn connect(&mut self) -> bool {
        // QUIC 설정
        let mut transport_config = TransportConfig::default();
        transport_config.keep_alive_interval(Some(Duration::from_secs(5)));

        // 자체 서명된 인증서 생성
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.serialize_der().unwrap();
        let priv_key = cert.serialize_private_key_der();
        let priv_key = rustls::PrivateKey(priv_key);
        let cert_chain = vec![rustls::Certificate(cert_der)];

        // 서버 설정
        let server_config = ServerConfig::with_single_cert(cert_chain, priv_key)
            .expect("Failed to create server config");
        let mut server_config = server_config;
        server_config.transport = Arc::new(transport_config);

        // 엔드포인트 생성
        let addr = format!("{}:{}", self.host, self.port).parse().unwrap();
        match Endpoint::server(server_config, addr) {
            Ok(endpoint) => {
                println!("Successfully created QUIC endpoint at {}", addr);
                self.endpoint = Some(endpoint);
                true
            }
            Err(e) => {
                eprintln!("Failed to create QUIC endpoint: {}", e);
                eprintln!("Retrying in {} seconds...", RETRY_DELAY.as_secs());
                false
            }
        }
    }

    fn print_transaction_info(&self, transaction: &Transaction) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis();

        println!("\n=== Transaction received at {} ===", timestamp);
        println!("Signatures:");
        for (i, sig) in transaction.signatures.iter().enumerate() {
            println!("  {}: {}", i, sig);
        }

        let message = &transaction.message;
        println!("\nRecent Blockhash: {}", message.recent_blockhash);
        
        println!("\nAccount Keys:");
        for (i, key) in message.account_keys.iter().enumerate() {
            let is_signer = message.is_signer(i);
            let is_writable = message.is_writable(i);
            println!("  {}: {} (signer: {}, writable: {})",
                i, key, is_signer, is_writable);
        }

        println!("\nInstructions:");
        for (i, instruction) in message.instructions.iter().enumerate() {
            self.print_instruction_info(i, instruction, message);
        }
        println!("=====================================\n");
    }

    fn print_instruction_info(
        &self,
        idx: usize,
        instruction: &CompiledInstruction,
        message: &Message,
    ) {
        println!("  Instruction {}:", idx);
        println!("    Program ID: {}", 
            message.account_keys[instruction.program_id_index as usize]);
        println!("    Input Data (hex): {}", 
            hex::encode(&instruction.data));
        println!("    Account Indexes: {:?}", instruction.accounts);
    }

    fn start_monitoring(&mut self) {
        println!("Starting transaction monitor...");
        println!("Press Ctrl+C to stop monitoring");

        let runtime = Runtime::new().unwrap();
        let monitor = Arc::new(Mutex::new(self.clone()));

        runtime.block_on(async {
            // 초기 연결 시도
            {
                let mut monitor_lock = monitor.lock().unwrap();
                if monitor_lock.endpoint.is_none() {
                    monitor_lock.connect();
                }
            }

            loop {
                let endpoint_option = {
                    let monitor_lock = monitor.lock().unwrap();
                    monitor_lock.endpoint.clone()
                };

                if let Some(endpoint) = endpoint_option {
                    if let Some(connecting) = endpoint.accept().await {
                        let monitor_clone = Arc::clone(&monitor);
                        tokio::spawn(async move {
                            match connecting.await {
                                Ok(connection) => {
                                    loop {
                                        match connection.accept_bi().await {
                                            Ok((mut _send, mut recv)) => {
                                                match recv.read_to_end(BUFFER_SIZE).await {
                                                    Ok(buffer) => {
                                                        if let Ok(transaction) = bincode::deserialize::<Transaction>(&buffer) {
                                                            let monitor_lock = monitor_clone.lock().unwrap();
                                                            monitor_lock.print_transaction_info(&transaction);
                                                        } else {
                                                            println!("Failed to deserialize transaction");
                                                            println!("Raw data (hex): {}", hex::encode(&buffer));
                                                        }
                                                    },
                                                    Err(e) => {
                                                        eprintln!("Error reading from stream: {}", e);
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                eprintln!("Error accepting stream: {}", e);
                                                break;
                                            }
                                        }
                                    }
                                }
                                Err(e) => eprintln!("Connection failed: {}", e),
                            }
                        });
                    }
                } else {
                    // 연결이 없으면 재연결 시도
                    let mut monitor_lock = monitor.lock().unwrap();
                    if !monitor_lock.connect() {
                        drop(monitor_lock); // 락 해제
                        thread::sleep(RETRY_DELAY);
                    }
                }
            }
        });
    }
}

// Clone 구현 추가
impl Clone for TransactionMonitor {
    fn clone(&self) -> Self {
        Self {
            host: self.host.clone(),
            port: self.port,
            endpoint: None, // 엔드포인트는 복제할 수 없으므로 None으로 설정
        }
    }
}

fn print_usage() {
    println!("Usage: transaction_monitor <host> <port>");
    println!("Example:");
    println!("  transaction_monitor 0.0.0.0 8004");
    println!("  transaction_monitor localhost 1024");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        print_usage();
        process::exit(1);
    }

    let host = args[1].clone();
    let port = match args[2].parse::<u16>() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Error: Port must be a number between 0 and 65535");
            print_usage();
            process::exit(1);
        }
    };

    let mut monitor = TransactionMonitor::new(host, port);
    monitor.start_monitoring();
}