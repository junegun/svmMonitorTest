// transaction_monitor/src/main.rs

use {
    solana_sdk::{
        transaction::Transaction,
        message::Message,
        instruction::CompiledInstruction,
    },
    std::{
        net::UdpSocket,
        time::{SystemTime, UNIX_EPOCH, Duration},
        env,
        process,
        thread,
        os::unix::io::AsRawFd,
    },
};

const BUFFER_SIZE: usize = 5232; // Solana max transaction size
const RETRY_DELAY: Duration = Duration::from_secs(5);

struct TransactionMonitor {
    host: String,
    port: u16,
    socket: Option<UdpSocket>,
}

impl TransactionMonitor {
    fn new(host: String, port: u16) -> Self {
        Self { 
            host,
            port,
            socket: None,
        }
    }

    fn connect(&mut self) -> bool {
        // 먼저 임의의 포트에 바인딩
        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to create UDP socket: {}", e);
                return false;
            }
        };

        // SO_REUSEADDR 옵션 설정 (Unix 시스템용)
        unsafe {
            let optval: libc::c_int = 1;
            if libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of_val(&optval) as libc::socklen_t,
            ) < 0 {
                eprintln!("Failed to set SO_REUSEADDR");
                return false;
            }
        }

        // 모니터링할 주소에 연결
        let target_addr = format!("{}:{}", self.host, self.port);
        match socket.connect(&target_addr) {
            Ok(_) => {
                println!("Successfully connected to {}", target_addr);
                self.socket = Some(socket);
                true
            }
            Err(e) => {
                eprintln!("Failed to connect to {}: {}", target_addr, e);
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

        loop {
            // 연결이 없으면 재연결 시도
            if self.socket.is_none() {
                if !self.connect() {
                    thread::sleep(RETRY_DELAY);
                    continue;
                }
            }

            let mut buffer = [0u8; BUFFER_SIZE];
            
            // 소켓이 Some인 경우에만 실행
            if let Some(socket) = &self.socket {
                match socket.recv(&mut buffer) {
                    Ok(size) => {
                        match bincode::deserialize::<Transaction>(&buffer[..size]) {
                            Ok(transaction) => {
                                self.print_transaction_info(&transaction);
                            }
                            Err(err) => {
                                eprintln!("Failed to deserialize transaction: {}", err);
                                println!("Raw data (hex): {}", hex::encode(&buffer[..size]));
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error receiving packet: {}", e);
                        // 소켓 에러 발생 시 재연결을 위해 socket을 None으로 설정
                        self.socket = None;
                        thread::sleep(RETRY_DELAY);
                    }
                }
            }
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