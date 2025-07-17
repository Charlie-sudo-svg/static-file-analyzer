use std::fs;
use std::fs::File;
use std::io::{Read, BufReader};
use std::path::Path;
use walkdir::WalkDir;
use sha2::{Sha256, Digest};
use chrono::{DateTime, Local};
use infer;

fn main() {
    let target = std::env::args().nth(1).expect("Usage: file_analyzer <file_or_dir>");
    let path = Path::new(&target);

    if path.is_file() {
        analyze_file(path);
    } else if path.is_dir() {
        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            if entry.path().is_file() {
                analyze_file(entry.path());
            }
        }
    } else {
        eprintln!("Path not found: {}", target);
    }
}

fn analyze_file(path: &Path) {
    println!("---");
    println!("File: {:?}", path);

    match fs::metadata(path) {
        Ok(metadata) => {
            let size = metadata.len();
            println!("Size: {} bytes", size);

            if let Ok(modified_time) = metadata.modified() {
                let datetime: DateTime<Local> = DateTime::from(modified_time);
                println!("Last Modified: {}", datetime.format("%Y-%m-%d %H:%M:%S"));
            }
        }
        Err(e) => {
            eprintln!("Failed to read metadata: {}", e);
            return;
        }
    }

    // === Type Detection ===
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open file: {}", e);
            return;
        }
    };

    let mut type_buffer = [0; 8192]; // Read first 8KB
    let _ = file.read(&mut type_buffer);

    if let Some(kind) = infer::get(&type_buffer) {
        println!("Detected Type: {} ({})", kind.mime_type(), kind.extension());
    } else {
        println!("Detected Type: Unknown");
    }

    // === SHA256 Hashing ===
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to reopen file for hashing: {}", e);
            return;
        }
    };

    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let _ = std::io::copy(&mut reader, &mut hasher);
    let result = hasher.finalize();
    println!("SHA256: {}", hex::encode(result));
}
