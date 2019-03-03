use std::io::prelude::*;
use std::io::Cursor;
use std::io::BufReader;
use std::str;
use xtsn::*;

fn main() -> std::io::Result<()> {
    let reader = std::fs::File::open("any.nca").expect("Put an nca at any.nca to decrypt!");

    let xts =
        CXTSN::new("<first half of header key>", "<second half>").expect("failed to create xts"); // XTSN is currently broken

    let mut header_block_enc = Vec::new();

    reader.take(0x4000).read_to_end(&mut header_block_enc)?;

    let header_block = xts
        .decrypt(header_block_enc.clone(), 0)
        .expect("failed to decrypt header (is header key wrong?)");

    std::fs::File::create("enc.bin")?.write_all(&header_block_enc)?;
    std::fs::File::create("dec.bin")?.write_all(&header_block)?;

    let mut header_reader = BufReader::new(Cursor::new(header_block));

    let mut signature1 = [0; 0x100];

    header_reader.read_exact(&mut signature1)?;

    let mut signature2 = [0; 0x100];

    header_reader.read_exact(&mut signature2)?;

    let mut magic = [0; 4];

    header_reader.read_exact(&mut magic)?;

    println!(
        "{}",
        str::from_utf8(&magic).expect("failed to convert bytes to str")
    );

    Ok(())
}
