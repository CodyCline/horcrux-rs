use serde::{Deserialize, Serialize};
use std::io::{BufRead, Seek, SeekFrom};
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, Read},
    path::{Path, PathBuf},
    time::SystemTime,
};

#[derive(Serialize, Deserialize, Clone)]
pub struct HorcruxHeader {
    pub canonical_file_name: String,
    pub timestamp: SystemTime,
    pub index: u8,
    pub total: u8,
    pub threshold: u8,
    #[serde(with = "serde_bytes")]
    pub nonce_fragment: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub key_fragment: Vec<u8>,
}

pub struct Horcrux {
    pub path: PathBuf,
    pub header: HorcruxHeader,
    pub contents: File,
}

impl Horcrux {
    pub fn new(path: PathBuf, header: HorcruxHeader, contents: File) -> Self {
        Self {
            path,
            header,
            contents,
        }
    }

    //This naively assumes you have already passed in a file ending in .horcrux or .hx
    // Open the file, read over each line and extract json content after reaching the -- HEADER -- marker. Stop scanning after reaching the -- BODY -- marker.
    // Once the body marker is reached we set the read pointer of the file contents to be after the header using seek.
    pub fn from_path(path: &Path) -> Result<Self, std::io::Error> {
        let mut file: File = OpenOptions::new().read(true).append(true).open(path)?;

        let mut total_bytes_scanned = 0;
        let reader = BufReader::new(file.by_ref());
        let mut header_content = String::new();
        let mut header_found: bool = false;

        for line in reader.lines() {
            let line = line?;
            total_bytes_scanned += line.len() + 1;

            if line == "-- HEADER --" {
                header_found = true;
                continue;
            }
            if header_found && line != "-- BODY --" {
                header_content.push_str(&line);
            }

            if line == "-- BODY --" {
                break; // Stop reading after reaching the body marker seek from here
            }
        }
        file.seek(SeekFrom::Start(total_bytes_scanned as u64))?;

        let header = serde_json::from_str(&header_content)?;

        Ok(Self {
            path: path.to_path_buf(),
            header,
            contents: file,
        })
    }

    pub fn formatted_header(index: u8, total: u8, json_header: String) -> String {
        let remaining = total - 1;
        let header = format!("?? THIS FILE IS A HORCRUX. \n?? IT IS ONE OF {total} HORCRUXES THAT EACH CONTAIN PART OF AN ORIGINAL FILE. \n?? THIS IS HORCRUX NUMBER {index} of {total}. \n?? IN ORDER TO RESURRECT THIS ORIGINAL FILE YOU MUST FIND THE OTHER {remaining} HORCRUXES AND THEN BIND THEM USING THE PROGRAM FOUND AT THE FOLLOWING URL \n?? https://github.com \n \n-- HEADER --\n{json_header} \n-- BODY --\n");
        header
    }
    
}