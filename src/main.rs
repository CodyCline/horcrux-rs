use std::path::PathBuf;
use atty::{isnt, Stream};
use clap::{error::ErrorKind, Parser, CommandFactory};
use cli::{Cli, Commands, BANNER};

use crate::utils::handle_std_in;

pub mod utils;
pub mod cli;
#[cfg(test)]
pub mod tests;

fn main() {
    println!("{BANNER}");
    let cli = Cli::parse();
    let mut err_command: clap::Command = Cli::command();

    match &cli.command {
        Commands::Split(args) => {
            let file = &args.file;
            let shards = &args.shards;
            let threshold = &args.threshold;
            let destination = &args.destination;
            if threshold > shards {
                let err = err_command.error(ErrorKind::ArgumentConflict, "Threshold cannot be larger than shards.");
                err.exit();
            }

            let source: PathBuf;

            //Check if std input exists first, then check if its 
            if isnt(Stream::Stdin) {
                let piped_source = handle_std_in().unwrap();
                source = piped_source;
            } else if file.is_some() {
                source = file.as_ref().unwrap().to_path_buf();
            } else {
                let err = err_command.error(ErrorKind::Format, "No input file detected.");
                    err.exit();
            }
            println!("🔮 Splitting your secret ...");
            let split_result = horcrux_rs::split(
                    &source, 
                    destination.as_ref().unwrap(), 
                    args.shards,
                    args.threshold
                );

            match split_result {
                Ok(_) => println!("🔒 Created {} horcruxes", shards),
                Err(e) => {
                    let err = err_command.error(ErrorKind::Format, e);
                    err.exit();
                }
            }
            
        }
        Commands::Bind(args) => {
            let source = &args.source;
            let destination = &args.destination;
            println!("📖 Recovering your secret ...");
            let result = horcrux_rs::bind(source.as_ref().unwrap(), destination.as_ref().unwrap());
            match result {
                Ok(_) => println!("🔑 Recovered the secret! "),
                Err(err) => {
                    let err = err_command.error(ErrorKind::ArgumentConflict, err);
                    err.exit();
                }
            }
        }
    }
}


