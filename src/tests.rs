#[cfg(test)]
// #[allow(unused_variables)]
mod tests {
    use chacha20poly1305::aead::OsRng;
    use horcrux_rs::crypto::{encrypt_file, decrypt_file};
    use horcrux_rs::horcrux::Horcrux;
    use rand::RngCore;
    use std::fs::{self, File, OpenOptions};
    use std::io::{LineWriter, Read, Write};
    use std::path::PathBuf;
    // Import the necessary modules and functions you want to test
    use sha2::{Digest, Sha256};


    #[test]
    fn it_works() {
        //Basically a sanity check
        let dir = PathBuf::from(".");

        let file_path = dir.join("secret.txt");

        let mut temp_file = File::create(file_path).expect("Should create temp file.");
        temp_file
            .write_all(b"Hello, world!")
            .expect("Should write to temp file");
        temp_file.flush().expect("Should write contents.");

        let split_result = horcrux_rs::split(&dir.join("secret.txt"), &dir, 1, 1);
        assert!(dir.join("secret.txt").exists());

        fs::remove_file(dir.join("secret.txt")).expect("File should be removed");
        assert!(!dir.join("secret.txt").exists());

        let bind_result = horcrux_rs::bind(&dir, &dir);

        assert!(bind_result.is_ok());
        assert!(split_result.is_ok());
        assert!(dir.join("secret.txt").exists());
        assert!(dir.join("secret_1_of_1.horcrux").exists());

        fs::remove_file(dir.join("secret.txt")).expect("Cleanup.");
        fs::remove_file(dir.join("secret_1_of_1.horcrux")).expect("Cleanup.");
    }

    #[test]
    fn it_has_matching_sha256_contents() {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 19];
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut nonce);

        let dir = PathBuf::from(".");

        let mut plaintext_file = OpenOptions::new()
            .read(true)
            .create(true)
            .write(true)
            .truncate(true)
            .open(dir.join("plaintext.txt"))
            .expect("Should create plaintext file");
        plaintext_file
            .write_all(b"Hello word")
            .expect("Should write to temp plaintext file.");

        let mut bytes_read: Vec<u8> = Vec::new();

        plaintext_file
            .read_to_end(&mut bytes_read)
            .expect("Get bytes from file");

        let mut pre_hasher = Sha256::new();
        pre_hasher.update(bytes_read);
        let plaintext_result = pre_hasher.finalize();

        let mut ciphertext_file = OpenOptions::new()
            .read(true)
            .create(true)
            .write(true)
            .truncate(true)
            .open(dir.join("ciphertext.txt"))
            .expect("Should create ciphertext file");

        let mut decrypted_file = OpenOptions::new()
            .read(true)
            .create(true)
            .write(true)
            .truncate(true)
            .open(dir.join("decrypted.txt"))
            .expect("Should create decrypted file");

        let encrypt = encrypt_file(&mut plaintext_file, &mut ciphertext_file, &key, &nonce);
        let decrypt = decrypt_file(&mut ciphertext_file, &mut decrypted_file, &key, &nonce);

        assert!(encrypt.is_ok());
        assert!(decrypt.is_ok());

        let mut decrypted: Vec<u8> = Vec::new();
        decrypted_file
            .read_to_end(&mut decrypted)
            .expect("Get bytes from file.");

        let mut post_hasher = Sha256::new();
        post_hasher.update(decrypted);
        let decrypted_result = post_hasher.finalize();

        assert_eq!(plaintext_result, decrypted_result);

        fs::remove_file(dir.join("plaintext.txt")).expect("Cleanup.");
        fs::remove_file(dir.join("ciphertext.txt")).expect("Cleanup.");
        fs::remove_file(dir.join("decrypted.txt")).expect("Cleanup.");
    }

    #[test]
    #[cfg(not(any(target_os = "windows")))]
    fn split_permission_fails() {
        let dir = PathBuf::from(".");
        let file_path = dir.join("cipher.txt");

        let mut temp_file = File::create(file_path).expect("Should create temp file.");
        temp_file
            .write_all(b"Hello, world!")
            .expect("Should write to temp file");
        temp_file.flush().expect("Should write contents.");
        let split_result = horcrux_rs::split(&dir, &PathBuf::from("/"), 1, 1);

        assert!(split_result.is_err());

        fs::remove_file(dir.join("cipher.txt")).expect("Cleanup");
    }

    #[test]
    fn split_creates_dir_success() {
        let dir = PathBuf::from(".");
        let file_path = dir.join("encoded.txt");

        let mut temp_file = File::create(file_path).expect("Should create temp file.");
        temp_file
            .write_all(b"Hello, world!")
            .expect("Should write to temp file");
        temp_file.flush().expect("Should write contents.");

        let split_result = horcrux_rs::split(&dir.join("encoded.txt"), &dir.join("test-folder"), 1, 1);
        assert!(dir
            .join("test-folder")
            .join("encoded_1_of_1.horcrux")
            .exists());
        assert!(split_result.is_ok());

        fs::remove_file(dir.join("test-folder").join("encoded_1_of_1.horcrux")).expect("Cleanup.");
        fs::remove_file(dir.join("encoded.txt")).expect("Cleanup.");
        fs::remove_dir_all(dir.join("test-folder")).expect("Cleanup.");
    }

    #[test]
    fn opening_malformed_horcrux_fails() {
        let dir = PathBuf::from(".");
        let malformed_header = "?? THIS FILE IS A HORCRUX. \n?? IT IS ONE OF 1 HORCRUXES THAT EACH CONTAIN PART OF AN ORIGINAL FILE. \n?? THIS IS HORCRUX NUMBER 1 of 1. \n?? IN ORDER TO RESURRECT THIS ORIGINAL FILE YOU MUST FIND THE OTHER 1 HORCRUXES AND THEN BIND THEM USING THE PROGRAM FOUND AT THE FOLLOWING URL \n?? https://github.com \n \n-- HEADER --\n\n-- BODY --\n{\"canonical_file_name\":\"private.txt\",\"timestamp\":{\"secs_since_epoch\":1691174227,\"nanos_since_epoch\":604324885},\"index\":1,\"total\":1,\"threshold\":1,\"nonce_fragment\":[1,29,175,135,122,191,64,83,153,167,113,215,164,25,29,227,5,27,31,237],\"key_fragment\":[1,35,220,103,43,133,86,103,215,147,13,242,187,182,86,111,43,62,121,165,73,139,82,104,118,174,19,6,13,28,33,149,232]}";
        
        
        let temp_file: File = OpenOptions::new()
            .read(true)
            .create(true)
            .write(true)
            .truncate(true)
            .open(dir.join("private_1_of_1.horcrux"))
            .expect("Create file");

        let mut writer = LineWriter::new(temp_file);
        writer
            .write_all(malformed_header.as_bytes())
            .expect("Should write to file.");
        writer.flush().expect("Should flush.");
        let try_horcrux = Horcrux::from_path(&dir.join("private_1_of_1.horcrux"));

        assert!(try_horcrux.is_err());

        fs::remove_file(dir.join("private_1_of_1.horcrux")).expect("Cleanup.");
    }

    #[test]
    fn binding_tampered_headers_fails() {
        let dir = PathBuf::from(".");
        let header = "?? THIS FILE IS A HORCRUX. \n?? IT IS ONE OF 1 HORCRUXES THAT EACH CONTAIN PART OF AN ORIGINAL FILE. \n?? THIS IS HORCRUX NUMBER 1 of 1. \n?? IN ORDER TO RESURRECT THIS ORIGINAL FILE YOU MUST FIND THE OTHER 1 HORCRUXES AND THEN BIND THEM USING THE PROGRAM FOUND AT THE FOLLOWING URL \n?? https://github.com \n \n-- HEADER --\n{\"canonical_file_name\":\"unknown.txt\",\"timestamp\":{\"secs_since_epoch\":1691177068,\"nanos_since_epoch\":989894876},\"index\":1,\"total\":2,\"threshold\":2,\"nonce_fragment\":[1,41,78,228,113,31,11,16,215,93,128,156,243,193,153,102,127,47,174,122],\"key_fragment\":[1,229,219,232,124,120,242,73,82,125,78,91,148,151,11,92,48,200,140,203,143,201,208,169,117,74,20,189,2,154,146,128,247]}\n-- BODY --\n";
        let tampered_header = "?? THIS FILE IS A HORCRUX. \n?? IT IS ONE OF 1 HORCRUXES THAT EACH CONTAIN PART OF AN ORIGINAL FILE. \n?? THIS IS HORCRUX NUMBER 1 of 1. \n?? IN ORDER TO RESURRECT THIS ORIGINAL FILE YOU MUST FIND THE OTHER 1 HORCRUXES AND THEN BIND THEM USING THE PROGRAM FOUND AT THE FOLLOWING URL \n?? https://github.com \n \n-- HEADER --\n{\"canonical_file_name\":\"unknown.txt\",\"timestamp\":{\"secs_since_epoch\":1691177068,\"nanos_since_epoch\":989894876},\"index\":2,\"total\":2,\"threshold\":2,\"nonce_fragment\":[2,25,190,33,172,47,149,50,238,225,96,131,188,3,104,19,46,80,247,105],\"key_fragment\":[1,229,219,232,124,120,242,73,82,125,78,91,148,151,11,92,48,200,140,203,143,201,208,169,117,74,20,189,2,154,146,128,247]}\n-- BODY --\n";

        let horcrux_file: File = OpenOptions::new()
            .read(true)
            .create(true)
            .write(true)
            .truncate(true)
            .open(dir.join("unknown_1_of_2.horcrux"))
            .expect("Create file");

        let tampered_horcrux_file: File = OpenOptions::new()
            .read(true)
            .create(true)
            .write(true)
            .truncate(true)
            .open(dir.join("unknown_2_of_2.horcrux"))
            .expect("Create file");
        let mut tampered_writer = LineWriter::new(tampered_horcrux_file);
        tampered_writer
            .write_all(tampered_header.as_bytes())
            .expect("Should write contents.");

        let mut writer = LineWriter::new(horcrux_file);
        writer.write_all(header.as_bytes()).expect("Should write.");

        let bind_result = horcrux_rs::bind(&dir, &dir);

        assert!(bind_result.is_err());
        assert_eq!(bind_result.unwrap_err().to_string(), "Not enough key fragments.");

        fs::remove_file(dir.join("unknown_1_of_2.horcrux")).expect("Cleanup.");
        fs::remove_file(dir.join("unknown_2_of_2.horcrux")).expect("Cleanup.");

    }

    #[test]
    fn binding_without_threshold_fails() {
        let dir = PathBuf::from(".");

        let file_path = dir.join("conspiracy.txt");

        let mut temp_file = File::create(file_path).expect("Should create temp file.");
        temp_file
            .write_all(b"Hello, world!")
            .expect("Should write to temp file");
        temp_file.flush().expect("Should write contents.");

        horcrux_rs::split(&dir.join("conspiracy.txt"), &dir, 2, 2).expect("Split should work.");

        fs::remove_file(dir.join("conspiracy.txt")).expect("File should be removed.");
        fs::remove_file(dir.join("conspiracy_1_of_2.horcrux")).expect("File should be removed.");

        assert!(!dir.join("conspiracy.txt").exists());

        let bind_result = horcrux_rs::bind(&dir, &dir);

        assert!(bind_result.is_err());
        assert_eq!(bind_result.unwrap_err().to_string(), "Cannot find enough horcruxes to recover `conspiracy.txt` found 1 matching horcruxes and 2 matches are required to recover the file.");
        fs::remove_file(dir.join("conspiracy_2_of_2.horcrux")).expect("Cleanup.");
    }

    #[test]
    fn binding_empty_file_fails() {
        let dir = PathBuf::from(".");
        let file_path = dir.join("classified_1_of_8.horcrux");

        File::create(file_path).expect("Should create temp file.");

        let bind_result = horcrux_rs::bind(&dir, &dir);
        let err_msg = bind_result.as_ref().unwrap_err();
        assert!(bind_result.is_err());
        assert_eq!(
            err_msg.to_string(),
            "EOF while parsing a value at line 1 column 0"
        );

        fs::remove_file(dir.join("classified_1_of_8.horcrux")).expect("Cleanup")
    }

    #[test]
    fn bind_creates_dir() {
        let dir = PathBuf::from(".");
        let file_path = dir.join("cryptic.txt");

        let mut temp_file = File::create(file_path).expect("Should create temp file.");
        temp_file
            .write_all(b"Hello, world!")
            .expect("Should write to temp file.");
        temp_file.flush().expect("Should write contents");
        horcrux_rs::split(&dir.join("cryptic.txt"), &dir, 1, 1).expect("Split should work.");

        horcrux_rs::bind(&dir, &dir.join("test-folder")).expect("Binding should work.");

        assert!(dir.join("test-folder").join("cryptic.txt").exists());

        fs::remove_file(dir.join("test-folder").join("cryptic.txt")).expect("Cleanup.");
        fs::remove_file(dir.join("cryptic_1_of_1.horcrux")).expect("Cleanup.");
        fs::remove_file(dir.join("cryptic.txt")).expect("Cleanup.");
        fs::remove_dir(dir.join("test-folder")).expect("Cleanup.");
    }
}
