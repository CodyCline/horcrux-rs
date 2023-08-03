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
        Err(format!("`{}` is not a file.", file.to_string_lossy()))
    }
}

//This function expects a smaller sized file and reads it into a buffer
//It then writes its contents to a temporary file and returns its location (path)
pub fn handle_std_in() -> Result<PathBuf, std::io::Error> {
    let mut temp_path = temp_dir();
    let mut buf: Vec<u8> = Vec::new();
    io::stdin()
        .lock()
        .read_to_end(&mut buf)
        .expect("Buffer overflow. Please pipe in a smaller secret.");
    let file_name = "secret.txt";
    temp_path.push(file_name);

    let mut temp_file = File::create(&temp_path)?;
    temp_file.write_all(&mut buf)?;

    Ok(temp_path)
}
