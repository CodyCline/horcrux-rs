use std::{
    env::temp_dir,
    fs::File,
    io::{self, Read, Write},
    ops::RangeInclusive,
    path::PathBuf,
};

const FRAGMENT_RANGE: RangeInclusive<usize> = 1..=255;

pub fn shards_in_range(s: &str) -> Result<u8, String> {
    let shards: usize = s.parse().map_err(|_| format!("`{s}` is not a number."))?;
    if FRAGMENT_RANGE.contains(&shards) {
        Ok(shards as u8)
    } else {
        Err(format!(
            "Shards must be between {} and {}.",
            FRAGMENT_RANGE.start(),
            FRAGMENT_RANGE.end()
        ))
    }
}

pub fn is_qualified_path(p: &str) -> Result<PathBuf, String> {
    let path: PathBuf = p.parse().map_err(|_| format!("`{p}` is not a path."))?;
    if !path.is_file() {
        Ok(path)
    } else {
        Err(format!("{} is not a path.", path.to_string_lossy()))
    }
}

pub fn is_qualified_file(f: &str) -> Result<PathBuf, String> {
    let file: PathBuf = f.parse().map_err(|_| format!("`{f}` is not a file."))?;
    if file.is_file() && !file.is_dir() && !file.is_symlink() {
        Ok(file)
    } else {
        Err(format!(
            "`{}` is not a file or does not exist.",
            file.to_string_lossy()
        ))
    }
}

const CHUNK_SIZE: usize = 4096;

//This function handles std input and reads the contents to a temporary file.
pub fn handle_std_in() -> Result<PathBuf, std::io::Error> {
    let mut temp_path = temp_dir();
    let file_name = "secret.txt";
    temp_path.push(file_name);

    let mut temp_file = File::create(&temp_path)?;

    let mut buf = [0u8; CHUNK_SIZE];
    loop {
        let bytes_read = io::stdin().lock().read(&mut buf)?;
        if bytes_read == 0 {
            break;
        }
        temp_file.write_all(&buf[..bytes_read])?;
    }
    Ok(temp_path)
}
