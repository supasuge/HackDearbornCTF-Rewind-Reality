use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::sync::atomic::{AtomicBool, Ordering};

fn handle_client(mut stream: TcpStream, flag: Arc<&str>) {
    let mut attempts = 0;
    let max_attempts = 3;
    let correct_answer = "Aruba Park";

    writeln!(stream, "Welcome to the challenge!").unwrap();
    writeln!(stream, "What is the name of the water park where the photo was taken?").unwrap();
    writeln!(stream, "You have {} attempts.", max_attempts).unwrap();

    let reader = BufReader::new(stream.try_clone().unwrap());

    for line in reader.lines() {
        let line = line.unwrap();
        attempts += 1;

        // Check if the input is correct (case-insensitive)
        if line.trim().eq_ignore_ascii_case(correct_answer) {
            writeln!(stream, "Correct! Here is your flag: {}", *flag).unwrap();
            break;
        } else {
            writeln!(stream, "Incorrect. Try again.").unwrap();
        }

        if attempts >= max_attempts {
            writeln!(stream, "You've used all {} attempts. Closing connection.", max_attempts).unwrap();
            break;
        }

        writeln!(stream, "Attempts remaining: {}", max_attempts - attempts).unwrap();
    }
    writeln!(stream, "Goodbye!").unwrap();
}

fn main() -> std::io::Result<()> {
    // The flag that will be sent upon correct submission
    let flag = Arc::new("ctf{example}");

    // Binding the server to a TCP socket to listen for connections
    let listener = TcpListener::bind("0.0.0.0:9999")?;
    println!("Listening on port 9999");

    // Loop to continuously accept connections
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let flag_clone = Arc::clone(&flag);
                thread::spawn(move || {
                    handle_client(stream, flag_clone);
                });
            }
            Err(e) => {
                println!("Connection failed: {}", e);
            }
        }
    }

    Ok(())
}
