extern crate cc;

fn main() {
    cc::Build::new()
        .file("src/aes.c")
        .file("src/ccrypto.c")
        .compile("libccrypto.a");
}
