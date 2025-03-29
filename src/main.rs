use std::io::{self, Write};

use anyhow::Result;

fn main() -> Result<()> {
    env_logger::init();

    let mut buf = String::new();
    loop {
        print!("mysql> ");
        io::stdout().flush().unwrap();
        buf.clear();
        io::stdin().read_line(&mut buf).unwrap();
        let sql = buf.trim();
        match sql {
            "exit" | "exit;" => break,
            _ => (),
        }
    }
    Ok(())
}
