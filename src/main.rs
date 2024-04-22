mod handler;

use clap::{Parser, Subcommand};

/// This CLI tool allows you to encrypt and decrypt data using a password and key name.
///
/// To encrypt data:
/// ```
/// aeadify -- -p my_password -k my_key encrypt "sensitive data"
/// ```
///
/// To decrypt data:
/// ```
/// aeadify -- -p my_password -k my_key decrypt
/// ```
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
    Encrypt {
        /// Specify the data to be encrypted
        input_data: String,
    },
    /// Decrypt data using a key name and password
    Decrypt,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = CliCommands::parse();

    match args.action {
        Action::Encrypt { input_data } => {
            handler::store_keys(&args.key, &input_data, &args.password)?;
        }
        Action::Decrypt => {
            let encrypted_string = handler::get_keys(&args.key, &args.password)?;
            println!("Decrypted data: {}", encrypted_string);
        }
    }

    Ok(())
}
