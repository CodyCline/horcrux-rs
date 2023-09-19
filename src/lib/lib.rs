
use chacha20poly1305::aead::OsRng;
use clap::builder::OsStr;
use horcrux::{HorcruxHeader, Horcrux};
use rand::RngCore;
use sharks::{Share, Sharks};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, LineWriter, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::SystemTime,
};
use anyhow::{anyhow, Error};

pub mod horcrux;
pub mod crypto;

pub fn split(
    source: &PathBuf,
    destination: &PathBuf,
    total: u8,
    threshold: u8,
) -> Result<(), anyhow::Error> {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 19];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut nonce);

    let crypto_shark = Sharks(threshold);

    //Break up key, nonce into same number of n fragments
    let key_dealer = crypto_shark.dealer(key.as_slice());
    let key_fragments: Vec<Share> = key_dealer.take(total as usize).collect();

    let nonce_dealer = crypto_shark.dealer(nonce.as_slice());
    let nonce_fragments: Vec<Share> = nonce_dealer.take(total as usize).collect();

    let timestamp = SystemTime::now();

    if !destination.exists() {
        let err = format!(
            "Cannot place horcruxes in directory `{}`. Try creating them in a different directory.",
            destination.to_string_lossy()
        );
        fs::create_dir_all(destination).expect(&err);
    }
    let default_file_name = OsStr::from("secret.txt");
    let default_file_stem = OsStr::from("secret");

    let canonical_file_name = &source
        .file_name()
        .unwrap_or(&default_file_name)
        .to_string_lossy();
    let file_stem = &source
        .file_stem()
        .unwrap_or(&default_file_stem)
        .to_string_lossy();
    let mut horcrux_files: Vec<File> = Vec::with_capacity(total as usize);

    for i in 0..total {
        let index = i + 1;
        let key_fragment = Vec::from(&key_fragments[i as usize]);
        let nonce_fragment = Vec::from(&nonce_fragments[i as usize]);
        let header = HorcruxHeader {
            canonical_file_name: canonical_file_name.to_string(),
            timestamp,
            index,
            total,
            threshold,
            nonce_fragment,
            key_fragment,
        };

        let json_header = serde_json::to_string(&header)?;
        let horcrux_filename = format!("{}_{}_of_{}.horcrux", file_stem, index, total);

        let horcrux_path = Path::new(&destination).join(&horcrux_filename);

        let horcrux_file: File = OpenOptions::new()
            .read(true)
            .create(true)
            .write(true)
            .truncate(true)
            .open(&horcrux_path)?;

        let contents = Horcrux::formatted_header(index, total, json_header);
        let mut line_writer = LineWriter::new(&horcrux_file);

        line_writer.write_all(contents.as_bytes())?;
        drop(line_writer);
        horcrux_files.push(horcrux_file);
    }

    /* Strategy:
    In this state all the horcrux files contain their headers and an empty body.
    In order to avoid calling `encrypt_file` on each file, instead, we
    calculate the byte length after the header of the first file and store it as a variable. 
    Next we encrypt the first file, and then use seek to skip over the index file headers and copy only the necessary contents to the rest.
    This is possible because the body content is the same for each file.
    */
    let mut contents_to_encrypt = File::open(source)?;
    let mut initial_horcrux: &File = &horcrux_files[0];

    let read_pointer: u64 = initial_horcrux.seek(SeekFrom::End(0))?;

    let mut horcrux_handle = initial_horcrux.try_clone()?;

    crypto::encrypt_file(&mut contents_to_encrypt, &mut horcrux_handle, &key, &nonce)?;

    for horcrux in horcrux_files.iter().skip(1) {
        initial_horcrux.seek(SeekFrom::Start(read_pointer))?;
        io::copy(&mut initial_horcrux, &mut horcrux.to_owned())?;
    }
    Ok(())
}


//Strategy is to find all files ending in .horcrux or .hx and then parse them. Next we filter them by matching timestamp and file name.
fn find_horcrux_file_paths(directory: &PathBuf) -> Result<Vec<PathBuf>, std::io::Error> {
    let paths = fs::read_dir(directory)?;

    let horcruxes: Vec<PathBuf> = paths
        .flat_map(|entry| {
            let entry = entry.expect("Failed to read directory entry.");
            let path = entry.path();

            if path.is_file() {
                if let Some(extension) = path.extension() {
                    if extension == "horcrux" || extension == "hx" {
                        return Some(path);
                    }
                }
            }

            None
        })
        .collect();
    Ok(horcruxes)
}

//Find all horcruxes in a directory that matches the first one found and attempt recovery.
pub fn bind(source: &PathBuf, destination: &PathBuf) -> Result<(), anyhow::Error> {
    let horcrux_paths = find_horcrux_file_paths(source)?;

    if horcrux_paths.is_empty() {
        let err = format!(
            "No horcrux files found in directory {}",
            source.to_string_lossy()
        );
        return Err(anyhow!(err));
    }

    let horcruxes: Vec<Horcrux> = horcrux_paths.into_iter().try_fold(
        Vec::new(),
        |mut acc: Vec<Horcrux>, entry: PathBuf| -> Result<Vec<Horcrux>, Error> {
            let hx = Horcrux::from_path(&entry)?;
            acc.push(hx);
            Ok(acc)
        },
    )?;

    let initial_horcrux = &horcruxes[0];
    let initial_header: &HorcruxHeader = &initial_horcrux.header;
    let threshold: u8 = initial_header.threshold;

    let mut key_shares: Vec<Share> = Vec::with_capacity(initial_header.total as usize);
    let mut nonce_shares: Vec<Share> = Vec::with_capacity(initial_header.total as usize);
    let mut matching_horcruxes: Vec<&Horcrux> = Vec::with_capacity(initial_header.total as usize);

    if !destination.exists() {
        fs::create_dir_all(destination)?;
    }

    for horcrux in &horcruxes {
        if horcrux.header.canonical_file_name == initial_header.canonical_file_name
            && horcrux.header.timestamp == initial_header.timestamp
        {
            let kshare: Share = Share::try_from(horcrux.header.key_fragment.as_slice())
                .map_err(|op| anyhow!(op))?;
            let nshare: Share = Share::try_from(horcrux.header.nonce_fragment.as_slice())
                .map_err(|op| anyhow!(op))?;
            key_shares.push(kshare);
            nonce_shares.push(nshare);
            matching_horcruxes.push(horcrux);
        }
    }

    if !(matching_horcruxes.is_empty() || matching_horcruxes.len() >= threshold.to_owned() as usize)
    {
        return Err(anyhow!(
            format!("Cannot find enough horcruxes to recover `{}` found {} matching horcruxes and {} matches are required to recover the file.",initial_header.canonical_file_name, matching_horcruxes.len(), threshold)
        ));
    }
    //Recover the secret
    let crypto_shark = Sharks(threshold);

    let key_result = crypto_shark
        .recover(&key_shares)
        .map_err(|_e| anyhow!("Not enough key fragments."))?;

    let nonce_result = crypto_shark
        .recover(&nonce_shares)
        .map_err(|_e| anyhow!("Not enough nonce fragments."))?;

    let key: [u8; 32] = key_result
        .try_into()
        .map_err(|_e| anyhow!("Cannot recover key fragment."))?;
    let nonce: [u8; 19] = nonce_result
        .try_into()
        .map_err(|_e| anyhow!("Cannot recover nonce fragment."))?;

    let mut recovered_file: File = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(destination.join(&initial_horcrux.header.canonical_file_name))?;

    let mut contents = initial_horcrux.contents.try_clone().unwrap();

    crypto::decrypt_file(&mut contents, &mut recovered_file, &key, &nonce)?;
    Ok(())
}