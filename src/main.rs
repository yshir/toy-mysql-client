use std::io::{self, Write};

use anyhow::Result;
use toy_mysql_client::connection::{Connection, ConnectionOptions};

fn main() -> Result<()> {
    env_logger::init();

    let mut conn = Connection::new(ConnectionOptions {
        username: String::from("root"),
        password: String::from("root"),
        database: String::from("test"),
        host: String::from("127.0.0.1"),
        port: 3306,
    })?;
    let mut buf = String::new();
    loop {
        print!("mysql> ");
        io::stdout().flush().unwrap();
        buf.clear();
        io::stdin().read_line(&mut buf).unwrap();
        let sql = buf.trim();
        match sql {
            "exit" | "exit;" => break,
            _ => {
                let result = conn.query(sql)?;
                println!("{}", result);
            }
        }
    }
    Ok(())
}
