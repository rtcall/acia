use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    /// Cipher type (128, 192, 256)
    #[arg(short, long, default_value_t = 128)]
    cipher: u32,

    /// Decrypt file
    #[arg(short, long)]
    decrypt: bool,

    /// Key for encryption and decryption
    key: String,

    /// Path to file to encrypt or decrypt
    path: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    acia::run(args.key, args.path, args.cipher, args.decrypt)
}
