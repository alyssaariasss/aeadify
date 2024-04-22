use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliCommands {
    /// Output file with encryption/decryption
    #[clap(short = 'o', long = "output-file")]
    output_file: Option<String>,
    #[clap(short = 'p', long = "password")]
    /// Password for encryption/decryption
    password: String,
    /// Crypto actions for the file
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand, Debug, Clone)]
enum Action {
    #[clap(short_flag = 'e', long_flag = "encrypt")]
    Encrypt {
        /// File to be encrypted
        input_file: String,
    },
    #[clap(short_flag = 'd', long_flag = "decrypt")]
    Decrypt {
        /// File to be decrypted
        input_file: String,
    },
}

fn main() {
    let args = CliCommands::parse();
    println!("{:#?}", args);
}
