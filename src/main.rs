mod handler;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliCommands {
    #[clap(short = 'p', long = "password")]
    /// Password used for encryption and decryption
    password: String,
    /// Key name to identify the encrypted data
    #[clap(short = 'k', long = "key")]
    key: String,
    /// Specify the action to perform on the data
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand, Debug, Clone)]
enum Action {
    /// Encrypt data using a password and specify a key name
    #[clap(short_flag = 'e', long_flag = "encrypt")]
    Encrypt {
        /// Specify the data to be encrypted
        input_data: String,
    },
    /// Decrypt data using a key name and password
    #[clap(short_flag = 'd', long_flag = "decrypt")]
    Decrypt {
        /// Specify the key name associated with the encrypted data
        key: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = CliCommands::parse();

    match args.action {
        Action::Encrypt { input_data } => {
            handler::store_keys(&args.key, &input_data, &args.password)?;
        }
        Action::Decrypt { key } => {
            let encrypted_string = handler::get_keys(&key, &args.password)?;
            println!("Decrypted data: {}", encrypted_string);
        }
    }

    Ok(())
}
