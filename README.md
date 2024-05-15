# AEADIFY

This project is a command-line interface tool for encrypting and decrypting data using a given password and key name. It also creates an `encrypted` folder where it stores encrypted data.

## Setup

1. Clone the repository:

```
git clone https://github.com/alyssaariasss/aeadify.git
cd aeadify
```

2. Install dependencies:

```
cargo build
```

## Usage

1. To encrypt data:

```
cargo run -- -p my_password -k my_key encrypt "sensitive data"
```

2. To decrypt data:

```
cargo run -- -p my_password -k my_key decrypt
```

## Options

- `-p`, `--password`: Password used for encryption and decryption.

- `-k`, `--key`: Key name to identify the encrypted data.

## Encrypted Folder

AEADIFY creates an encrypted folder where it stores encrypted data. The folder is located at ./encrypted.
