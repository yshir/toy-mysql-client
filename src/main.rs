use std::io::{self, Write};

use anyhow::Result;
use clap::Parser;
use toy_mysql_client::connection::Connection;

#[derive(Parser, Debug)]
#[clap(disable_help_flag = true)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short = 'h', default_value_t = String::from("127.0.0.1"))]
    host: String,
    #[arg(short = 'P', default_value_t = 3306)]
    port: u16,
    #[arg(short = 'u', default_value_t = String::from("root"))]
    username: String,
    #[arg(short = 'p', default_value_t = String::from("root"))]
    password: String,
    #[arg(short = 'D', default_value_t = String::from("test"))]
    database: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut conn = Connection::new(
        &args.host,
        args.port,
        &args.username,
        &args.password,
        &args.database,
    )?;
    conn.handshake()?;

    let mut buf = String::new();
    print!("mysql> ");
    loop {
        io::stdout().flush().unwrap();
        buf.clear();
        io::stdin().read_line(&mut buf).unwrap();
        let input = buf.trim();
        match input {
            "exit" => break,
            "" => print!("mysql> "),
            _ => println!("unknown command: {}", input),
        }
    }

    Ok(())
}
