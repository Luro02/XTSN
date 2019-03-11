/// This is a port of switchfs's ccrypto that allows to decrypt Nintendo specific stuff...
/// https://github.com/ihaveamac/switchfs
/// The entire C-Code stays under the original license!
/// The main.rs is licensed under the MIT license

// The MIT License (MIT)
//
// Copyright (c) 2018 Luro02
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software
// and associated documentation files (the "Software"), to deal in the Software without restriction,
// including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the Software is furnished to
// do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial
// portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
// NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
/*
TODO:
    - add full logging support!
    - handle errors in C-Code via int return?
    - write benchmarks
    - make this thing a library
    - speed comparison?!
    - rework the error messages...
*/
#[macro_use]
extern crate log;
use crypto;
use hex;

use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use crypto::aes;
use crypto::buffer;
use std::io::Cursor;
use std::iter::Iterator;

extern "C" {
    fn aes_xtsn_encrypt(
        buffer: *mut u8,
        len: u64,
        key: *mut u8,
        tweakin: *mut u8,
        sectoroffsethi: u64,
        sectoroffsetlo: u64,
        sector_size: u32,
    );
    fn aes_xtsn_decrypt(
        buffer: *mut u8,
        len: u64,
        key: *mut u8,
        tweakin: *mut u8,
        sectoroffsethi: u64,
        sectoroffsetlo: u64,
        sector_size: u32,
    );
}

/// This structure is the C-Version of the XTSN decryptor
/// It works the same way the XTSN version does!
pub struct CXTSN {
    crypt: [u8; 0x10], // contains the key used for decrypting
    tweak: [u8; 0x10], // contains the key used for encrypting
}

impl CXTSN {
    /// initializes a new Cryptor
    /// it requires 2 keys:
    /// + crypt to decrypt
    /// + tweak to encrypt
    /// they can be the same but shouldn't !!!
    #[must_use]
    pub fn new(crypt: &str, tweak: &str) -> Result<Self, String> {
        let tcrypt = match hex::decode(crypt) {
            Ok(res) => res,
            Err(err) => return Err(format!("[l{:03}] Error decoding crypt: {}", line!(), err)),
        };
        let ttweak = match hex::decode(tweak) {
            Ok(res) => res,
            Err(err) => return Err(format!("[l{:03}] Error decoding tweak: {}", line!(), err)),
        };
        debug!(
            "Initialized XTSN struct with the following keys: tcrypt: {:?} and ttweak {:?} ",
            &tcrypt, &ttweak
        );
        Ok(Self {
            // https://stackoverflow.com/a/29570662/7766117
            crypt: {
                // converts a vector into an array:
                let mut array = [0u8; 0x10];
                let bytes = &tcrypt.as_slice()[..array.len()]; // panics if not enough data
                array.copy_from_slice(bytes);
                array
            },
            tweak: {
                // converts a vector into an array:
                let mut array = [0u8; 0x10];
                let bytes = &ttweak.as_slice()[..array.len()]; // panics if not enough data
                array.copy_from_slice(bytes);
                array
            },
        })
    }

    /// This function is used to encrypt data. It works only with buffers,
    /// that are a multiple of 0x200! The function doesn't check the buffer so
    /// it will silently ignore any trailing bytes in the buffer!
    ///
    /// # Example
    ///
    /// ```
    /// extern crate xtsn;
    ///
    /// fn main() {
    ///     let mut data = b"Hello XTSN".to_vec();
    ///     // the string is not 0x200 bytes:
    ///     while data.len() != 0x200 {
    ///         data.push(0);
    ///     }
    ///     let xts = match xtsn::CXTSN::new("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    ///                                     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") {
    ///         Ok(res) => res,
    ///         Err(e) => panic!(e),
    ///     };
    ///     let ret = match xts.encrypt(data, 0) {
    ///         Ok(res) => res,
    ///         Err(e) => panic!(e),
    ///     };
    ///     println!("{:?}", &ret);
    /// }
    /// ```
    #[must_use]
    pub fn encrypt(&self, buffer: Vec<u8>, sector_off: usize) -> Result<Vec<u8>, String> {
        let mut result: Vec<u8> = buffer;
        let mut crypt = self.crypt.clone();
        let mut tweak = self.tweak.clone();
        unsafe {
            aes_xtsn_encrypt(
                result.as_mut_ptr(),
                result.len() as u64,
                crypt.as_mut_ptr(),
                tweak.as_mut_ptr(),
                (sector_off as u64).wrapping_shr(64) & 0xFFFFFFFFFFFFFFFF,
                (sector_off as u64) & 0xFFFFFFFFFFFFFFFF,
                0x200,
            );
        }
        Ok(result)
    }

    /// This function is used to decrypt data. It works only with buffers,
    /// that are a multiple of 0x200! The function doesn't check the buffer so
    /// it will silently ignore any trailing bytes in the buffer!
    /// This function is currently broken and need some debugging, or you can just use the CXTSN
    /// version which just works :3
    ///
    /// # Example
    ///
    /// ```
    /// extern crate xtsn;
    ///
    /// fn main() {
    ///     let mut data = b"Hello XTSN".to_vec();
    ///     // the string is not 0x200 bytes:
    ///     while data.len() != 0x200 {
    ///         data.push(0);
    ///     }
    ///     let xts = match xtsn::CXTSN::new("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    ///                                      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") {
    ///         Ok(res) => res,
    ///         Err(e) => panic!(e),
    ///     };
    ///     let ret = match xts.decrypt(data, 0) {
    ///         Ok(res) => res,
    ///         Err(e) => panic!(e),
    ///     };
    ///     println!("{:?}", &ret);
    /// }
    /// ```
    #[must_use]
    pub fn decrypt(&self, buffer: Vec<u8>, sector_off: usize) -> Result<Vec<u8>, String> {
        let mut result: Vec<u8> = buffer;
        let mut crypt = self.crypt.clone();
        let mut tweak = self.tweak.clone();
        unsafe {
            aes_xtsn_decrypt(
                result.as_mut_ptr(),
                result.len() as u64,
                crypt.as_mut_ptr(),
                tweak.as_mut_ptr(),
                (sector_off as u64).wrapping_shr(64) & 0xFFFFFFFFFFFFFFFF,
                (sector_off as u64) & 0xFFFFFFFFFFFFFFFF,
                0x200,
            );
        }
        Ok(result)
    }

    pub fn pack(data: u128) -> Result<Vec<u8>, String> {
        let mut result: Vec<u8> = Vec::new();
        match result.write_u128::<LE>(data) {
            Ok(res) => res,
            Err(err) => return Err(format!("{:?}", err)),
        }
        // TODO: useless?!
        while result.len() != 16 {
            result.push(0);
        }
        Ok(result)
    }

    pub fn unpack(data: Vec<u8>) -> Result<u128, String> {
        let mut rdr = Cursor::new(data);
        let result = rdr.read_u128::<LE>();
        match result {
            Ok(res) => Ok(res),
            Err(err) => Err(format!("{:?}", err)),
        }
    }

    pub fn xor(s1: &Vec<u8>, s2: &Vec<u8>) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();
        for (a, b) in Iterator::zip(s1.iter(), s2.iter()) {
            result.push(a ^ b);
        }
        result
    }
}

/// XTSN works the same as CXTSN, the only difference is, that the XTSN version is written in pure
/// Rust and handles Errors. This means that the Result actually returns usefull stuff, that you should
/// defenitly parse!
pub struct XTSN {
    crypt: [u8; 0x10], // contains the key used for decrypting
    tweak: [u8; 0x10], // contains the key used for encrypting
}

impl XTSN {
    /// initializes a new Cryptor
    /// it requires 2 keys:
    /// + crypt to decrypt
    /// + tweak to encrypt
    /// they can be the same but shouldn't !!!
    #[must_use]
    pub fn new(crypt: &str, tweak: &str) -> Result<Self, String> {
        let tcrypt = match hex::decode(crypt) {
            Ok(res) => res,
            Err(err) => return Err(format!("[l{:03}] Error decoding crypt: {}", line!(), err)),
        };
        let ttweak = match hex::decode(tweak) {
            Ok(res) => res,
            Err(err) => return Err(format!("[l{:03}] Error decoding tweak: {}", line!(), err)),
        };
        debug!(
            "Initialized XTSN struct with the following keys: tcrypt: {:?} and ttweak {:?} ",
            &tcrypt, &ttweak
        );
        Ok(Self {
            // https://stackoverflow.com/a/29570662/7766117
            crypt: {
                // converts a vector into an array:
                let mut array = [0u8; 0x10];
                let bytes = &tcrypt.as_slice()[..array.len()]; // panics if not enough data
                array.copy_from_slice(bytes);
                array
            },
            tweak: {
                // converts a vector into an array:
                let mut array = [0u8; 0x10];
                let bytes = &ttweak.as_slice()[..array.len()]; // panics if not enough data
                array.copy_from_slice(bytes);
                array
            },
        })
    }

    /// This function is used to encrypt data. It works only with buffers,
    /// that are a multiple of 0x200! The function doesn't check the buffer so
    /// it will silently ignore any trailing bytes in the buffer!
    ///
    /// # Example
    ///
    /// ```
    /// extern crate xtsn;
    ///
    /// fn main() {
    ///     let mut data = b"Hello XTSN".to_vec();
    ///     // the string is not 0x200 bytes:
    ///     while data.len() != 0x200 {
    ///         data.push(0);
    ///     }
    ///     let xts = match xtsn::XTSN::new("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    ///                                     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") {
    ///         Ok(res) => res,
    ///         Err(e) => panic!(e),
    ///     };
    ///     let ret = match xts.decrypt(data, 0) {
    ///         Ok(res) => res,
    ///         Err(e) => panic!(e),
    ///     };
    ///     println!("{:?}", &ret);
    /// }
    /// ```
    #[must_use]
    pub fn decrypt(&self, buffer: Vec<u8>, sector_off: usize) -> Result<Vec<u8>, String> {
        let mut result: Vec<u8> = Vec::new();
        for i in 0..buffer.len() / 0x200 {
            let pos: u128 = (sector_off + i) as u128;
            // generate the tweak:
            let mut tweak = {
                let mut data = match Self::pack(pos) {
                    Err(err) => return Err(err),
                    Ok(res) => res,
                };
                let mut tbuffer = [0u8; 16];
                // encrypt the data
                let mut read_buffer = buffer::RefReadBuffer::new(&mut data);
                let mut write_buffer = buffer::RefWriteBuffer::new(&mut tbuffer);
                let mut c_enc = aes::ecb_encryptor(
                    aes::KeySize::KeySize128,
                    &self.tweak,
                    crypto::blockmodes::NoPadding, // could also be NoPadding?!
                );
                match c_enc.encrypt(&mut read_buffer, &mut write_buffer, true) {
                    Err(e) => return Err(format!("[l{:03}] Encrypting failed: {:?}", line!(), e)),
                    _ => {}
                };
                tbuffer.to_vec()
            };
            for j in 0..0x200 / 16 {
                let off = i * 0x200 + j * 16;
                let mut blk = {
                    let mut tbuffer = [0u8; 16].to_vec();
                    let mut tblk = Self::xor(&buffer[off..off + 16].to_vec(), &tweak);

                    let mut read_buffer = buffer::RefReadBuffer::new(&mut tblk);
                    let mut write_buffer = buffer::RefWriteBuffer::new(&mut tbuffer);
                    // for some reason I have to create a new decryptor -.-
                    let mut dec = aes::ecb_decryptor(
                        aes::KeySize::KeySize128,
                        &self.crypt,
                        crypto::blockmodes::NoPadding,
                    );
                    match dec.decrypt(&mut read_buffer, &mut write_buffer, true) {
                        Err(e) => {
                            return Err(format!("[l{:03}] Decrypting failed: {:?}", line!(), e))
                        }
                        _ => {}
                    };
                    Self::xor(&tbuffer, &tweak)
                };

                // this thing generates the new tweak, don't ask me how this works...
                tweak = {
                    let mut ttweak = match Self::unpack(tweak.to_vec()) {
                        Ok(res) => res,
                        Err(err) => return Err(err),
                    };
                    // was written to debug bit shifting
                    debug!(
                        "in1: {:0128b}\nin2: {:0128b}\nout: {:0128b}\n---------------------",
                        ttweak,
                        1u128.wrapping_shl(127),
                        ttweak & 1u128.wrapping_shl(127)
                    );
                    if ttweak & 1u128.wrapping_shl(127) > 0 {
                        ttweak = ((ttweak & !1u128.wrapping_shl(127)) << 1) ^ 0x87;
                    } else {
                        ttweak <<= 1;
                    }
                    match Self::pack(ttweak) {
                        Ok(res) => res,
                        Err(err) => return Err(err),
                    }
                };
                result.append(&mut blk);
            }
        }
        Ok(result)
    }

    /// This function is used to encrypt data. It works just only with buffers,
    /// that are a multiple of 0x200! The function doesn't check the buffer so
    /// it will silently ignore any trailing bytes in the buffer!
    /// This function is currently broken and need some debugging, or you can just use the CXTSN
    /// version which just works :3
    ///
    /// # Example
    ///
    /// ```
    /// extern crate xtsn;
    ///
    /// fn main() {
    ///     let mut data = b"Hello XTSN".to_vec();
    ///     // the string is not 0x200 bytes:
    ///     while data.len() != 0x200 {
    ///         data.push(0);
    ///     }
    ///     let xts = match xtsn::XTSN::new("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    ///                                     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") {
    ///         Ok(res) => res,
    ///         Err(e) => panic!(e),
    ///     };
    ///     let ret = match xts.encrypt(data, 0) {
    ///         Ok(res) => res,
    ///         Err(e) => panic!(e),
    ///     };
    ///     println!("{:?}", &ret);
    /// }
    /// ```
    #[must_use]
    pub fn encrypt(&self, buffer: Vec<u8>, sector_off: usize) -> Result<Vec<u8>, String> {
        let mut result: Vec<u8> = Vec::new();
        for i in 0..buffer.len() / 0x200 {
            let pos: u128 = (sector_off + i) as u128;
            // generate the tweak for the first 16 bytes:
            let mut tweak = {
                let mut data = match Self::pack(pos) {
                    Ok(res) => res,
                    Err(err) => return Err(err),
                };
                let mut tbuffer = [0u8; 16];
                let mut read_buffer = buffer::RefReadBuffer::new(&mut data);
                let mut write_buffer = buffer::RefWriteBuffer::new(&mut tbuffer);
                let mut c_enc = aes::ecb_encryptor(
                    aes::KeySize::KeySize128,
                    &self.crypt,
                    crypto::blockmodes::NoPadding,
                );
                match c_enc.encrypt(&mut read_buffer, &mut write_buffer, true) {
                    Err(e) => return Err(format!("[l{:03}] Encrypting failed: {:?}", line!(), e)),
                    _ => {}
                };
                tbuffer.to_vec()
            };
            for j in 0..0x200 / 16 {
                let off = i * 0x200 + j * 16;
                let mut blk = {
                    let mut tbuffer = [0u8; 16].to_vec();
                    let mut tblk = Self::xor(&buffer[off..off + 16].to_vec(), &tweak);

                    let mut read_buffer = buffer::RefReadBuffer::new(&mut tblk);
                    let mut write_buffer = buffer::RefWriteBuffer::new(&mut tbuffer);
                    // for some reason I have to create a new decryptor -.-
                    let mut c_dec = aes::ecb_decryptor(
                        aes::KeySize::KeySize128,
                        &self.tweak,
                        crypto::blockmodes::NoPadding,
                    );
                    match c_dec.decrypt(&mut read_buffer, &mut write_buffer, true) {
                        Err(e) => {
                            return Err(format!("[l{:03}] Decrypting failed: {:?}", line!(), e))
                        }
                        _ => {}
                    };
                    Self::xor(&tbuffer, &tweak)
                };

                tweak = {
                    let mut ttweak = match Self::unpack(tweak.to_vec()) {
                        Ok(res) => res,
                        Err(err) => return Err(err),
                    };
                    // shows how the comparison works:
                    debug!(
                        "in1: {:0128b}\nin2: {:0128b}\nout: {:0128b}\n---------------------",
                        ttweak,
                        1u128.wrapping_shl(127),
                        ttweak & 1u128.wrapping_shl(127)
                    );
                    if ttweak & 1u128.wrapping_shl(127) > 0 {
                        ttweak = ((ttweak & !1u128.wrapping_shl(127)) << 1) ^ 0x87;
                    } else {
                        ttweak <<= 1;
                    }
                    match Self::pack(ttweak) {
                        Ok(res) => res,
                        Err(err) => return Err(err),
                    }
                };
                result.append(&mut blk);
            }
        }
        Ok(result)
    }

    pub fn pack(data: u128) -> Result<Vec<u8>, String> {
        let mut result: Vec<u8> = Vec::new();
        match result.write_u128::<LE>(data) {
            Ok(res) => res,
            Err(err) => return Err(format!("{:?}", err)),
        }
        // TODO: useless?!
        while result.len() != 16 {
            result.push(0);
        }
        Ok(result)
    }

    pub fn unpack(data: Vec<u8>) -> Result<u128, String> {
        let mut rdr = Cursor::new(data);
        let result = rdr.read_u128::<LE>();
        match result {
            Ok(res) => Ok(res),
            Err(err) => Err(format!("{:?}", err)),
        }
    }

    pub fn xor(s1: &Vec<u8>, s2: &Vec<u8>) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();
        for (a, b) in Iterator::zip(s1.iter(), s2.iter()) {
            result.push(a ^ b);
        }
        result
    }
}

#[cfg(test)]
mod test {
    use super::CXTSN;

    #[test]
    fn test_c_encrypt() {
        let xts = match CXTSN::new(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        ) {
            Ok(res) => res,
            Err(err) => panic!("Error occured {}", err),
        };
        let mut test_string = b"Hello CXTSN!".to_vec();
        while test_string.len() != 0x200 {
            test_string.push(0);
        }
        let mut ret = xts.encrypt(test_string, 0).unwrap();
        while ret.len() != 12 {
            ret.pop();
        }
        println!("ret: {:?}", ret);
        // assert_eq!();
    }
}
