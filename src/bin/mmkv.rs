use clap::Parser;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Clone)]
struct HexArgs(Vec<u8>);

impl FromStr for HexArgs {
    type Err = std::num::ParseIntError;

    fn from_str(hex_str: &str) -> Result<Self, Self::Err> {
        let result = (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
            .collect::<Result<Vec<u8>, Self::Err>>()?;
        Ok(HexArgs(result))
    }
}

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to mmkv store
    #[arg(short = 'i')]
    input: PathBuf,

    /// Path to decrypted mmkv file.
    #[arg(short = 'o', long)]
    output: PathBuf,

    /// Key for MMKV store.
    #[arg(short = 'k')]
    key: HexArgs,

    /// Path to corresponding `.crc` file.
    /// Default: mmkv + ".crc"
    #[arg(short = 'c', long = "crc_file")]
    mmkv_crc: Option<PathBuf>,
}

#[derive(Debug, Error)]
enum CliError {
    #[error("I/O error from source: {0}")]
    IOErrorSource(std::io::Error),
    #[error("I/O error from destination: {0}")]
    IOErrorDestination(std::io::Error),

    #[error("Error when deciphering enciphered file: {0}")]
    CipherError(mmkv_parser::Error),
}

fn mmkv_decrypt(args: &Args) -> Result<(), CliError> {
    let crc_file = match &args.mmkv_crc {
        Some(p) => p.clone(),
        None => {
            let mut crc_path = args.input.clone();
            let crc_name = format!(
                "{}.crc",
                args.input
                    .file_name()
                    .unwrap_or_default()
                    .to_str()
                    .unwrap_or_default()
            );
            crc_path.set_file_name(crc_name);
            crc_path
        }
    };

    let mut f_crc = File::open(crc_file).map_err(CliError::IOErrorSource)?;
    let mut f_mmkv = File::open(&args.input).map_err(CliError::IOErrorSource)?;

    let mut crc_file_body = Vec::with_capacity(4096);
    f_crc
        .read_to_end(&mut crc_file_body)
        .map_err(CliError::IOErrorSource)?;

    let crc_hdr = mmkv_parser::cipher::MmkvCrcHeader::from_bytes(crc_file_body)
        .map_err(CliError::CipherError)?;
    let mut mmkv_body = Vec::with_capacity(4096);
    f_mmkv
        .read_to_end(&mut mmkv_body)
        .map_err(CliError::IOErrorSource)?;
    mmkv_body.resize(crc_hdr.real_size + 4, 0); // trim buffer
    mmkv_parser::cipher::decrypt(&crc_hdr, &args.key.0, &mut mmkv_body)
        .map_err(CliError::CipherError)?;

    let output_path = &args.output;
    let mut output_file = File::create(output_path).map_err(CliError::IOErrorDestination)?;
    output_file
        .write_all(&mmkv_body)
        .map_err(CliError::IOErrorDestination)?;

    eprintln!("done, {} bytes processed.", mmkv_body.len());

    Ok(())
}

fn main() {
    let args = Args::parse();

    match mmkv_decrypt(&args) {
        Ok(_) => process::exit(0),
        Err(err) => {
            eprintln!("failed to decrypt mmkv: {}", err);
            process::exit(1);
        }
    }
}
