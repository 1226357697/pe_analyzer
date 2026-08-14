use anyhow::{Ok, Result as AnyhowResult, anyhow};
use std::env;

mod base_block;
mod disassember;
mod object;
mod parser;

fn do_parse(path: &str) -> AnyhowResult<()> {
    let parser = parser::PEParser::make(path)?;
    let mut object = object::Object::make();

    if let Err(e) = parser.parse(&mut object) {
        eprintln!("Error parsing PE file: {}", e);
        return Err(e);
    }

    object.print_all();

    Ok(())
}

fn print_help() {
    println!("Usage: pe-parser <exe_path>");
    println!("\tExample: pe-parser C:\\Windows\\System32\\notepad.exe");
}
fn main() -> AnyhowResult<()> {
    env_logger::init();

    let first_arg = env::args()
        .nth(1)
        .ok_or_else(|| anyhow!("missing required argument <exe_path>"))?;
    match first_arg.as_str() {
        "--help" | "-h" | "-?" => {
            print_help();
            return Ok(());
        }
        path => {
            do_parse(path)?;
        }
    }

    Ok(())
}
