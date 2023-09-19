//Solution adapated from and made possible by: https://kerkour.com/rust-file-encryption
use anyhow::anyhow;
use chacha20poly1305::{
    aead::stream::{self},
    KeyInit, XChaCha20Poly1305,
};
use std::{
    fs::File,
    io::{Read, Write},
};

pub fn encrypt_file(
    source: &mut File,
    destination: &mut File,
    key: &[u8; 32],
    nonce: &[u8; 19],
) -> Result<(), anyhow::Error> {
    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_slice().into());
    const BUFFER_LENGTH: usize = 500 + 16;
    let mut buffer = [0u8; BUFFER_LENGTH];

    loop {
        let read_count = source.read(&mut buffer)?;
        if read_count == BUFFER_LENGTH {
            let ciphertext = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!(err))?;
            destination.write_all(&ciphertext)?;
        } else {
            let ciphertext = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!(err))?;
            destination.write_all(&ciphertext)?;
            break;
        }
    }
    Ok(())
}

pub fn decrypt_file(
    encrypted_source: &mut File,
    destination: &mut File,
    key: &[u8; 32],
    nonce: &[u8; 19],
) -> Result<(), anyhow::Error> {
    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.into());

    const BUFFER_LENGTH: usize = 500 + 16;
    let mut buffer = [0u8; BUFFER_LENGTH];

    loop {
        let read_count = encrypted_source.read(&mut buffer)?;
        if read_count == BUFFER_LENGTH {
            let plaintext = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!(err))?;
            destination.write_all(&plaintext)?;
        } else if read_count == 0 {
            break;
        } else {
            let plaintext = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!(err))?;
            destination.write_all(&plaintext)?;
            break;
        }
    }
    Ok(())
}
