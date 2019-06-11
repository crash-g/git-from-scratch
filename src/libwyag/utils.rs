//! Various utility functions

use std::{
    fs,
    fs::File,
    io::prelude::*,
    path::{Path, PathBuf},
    result::Result::Err,
};

use super::Result;

/// Replace `from` with `to` in `source`.
pub fn replace<T>(source: &[T], from: &[T], to: &[T]) -> Vec<T>
where
    T: Clone + PartialEq
{
    let mut result = source.to_vec();
    let from_len = from.len();
    let to_len = to.len();

    let mut i = 0;
    while i + from_len <= result.len() {
        if result[i..].starts_with(from) {
            result.splice(i..i + from_len, to.iter().cloned());
            i += to_len;
        } else {
            i += 1;
        }
    }

    result
}

#[test]
fn test_replace() {
    assert_eq!(b"efcd".to_vec(), replace(b"abcd", b"ab", b"ef"));
    assert_eq!(b"afcf".to_vec(), replace(b"abcb", b"b", b"f"));
    assert_eq!(b"ajjjbe".to_vec(), replace(b"abbbe", b"bb", b"jjj"));
    assert_eq!(b"abjjj".to_vec(), replace(b"abc", b"c", b"jjj"));
    assert_eq!(b"ahhe".to_vec(), replace(b"abbbbe", b"bb", b"h"));
    assert_eq!(vec![Some(0), Some(1), Some(3), Some(4)],
               replace(&[None, Some(3), Some(4)], &[None], &[Some(0), Some(1)]));
}

pub fn create_directory<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();
    if path.exists() {
        if path.is_dir() {
            Ok(())
        } else {
            Err(format!("{:?} is not a directory", path))
        }
    } else {
        println!("Creating directory {:?}", path);
        fs::create_dir_all(&path)
            .map_err(|_| format!("Cannot create {:?} directory", path))?;
        Ok(())
    }
}

pub fn read_directory_content<P: AsRef<Path>>(path: P) -> Result<Vec<PathBuf>> {
    let path = path.as_ref();
    let mut results = Vec::new();
    for entry in path.read_dir()
        .map_err(|e| format!("Cannot read a directory entry from {:?}: {}", path, e))? {
        if let Ok(entry) = entry {
            results.push(entry.path())
        }
    }
    Ok(results)
}

pub fn check_is_empty<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();
    if path.exists() {
        if !path.is_dir() {
            Err(format!("{:?} exists and is not a directory", path))
        } else {
            let content = path.read_dir()
                .map_err(|_| format!("Cannot read the content of {:?}", path))?;
            if let Some(_) = content.into_iter().next() {
                Err(format!("{:?} is not empty", path))
            } else {
                Ok(())
            }
        }
    } else {
        Err(format!("{:?} does not exist", path))
    }
}

pub fn read_file<P: AsRef<Path>>(file_path: P) -> Result<File> {
    let file_path = file_path.as_ref();
    if let Some(parent) = file_path.parent() {
        if parent.is_dir() {
            Ok(File::open(file_path)
               .map_err(|_| format!("Cannot open {:?} file", file_path))?)
        } else {
            Err(format!("{:?} is not a directory", parent))
        }
    } else {
        Err(format!("Path not valid: {:?}", file_path))
    }
}

pub fn read_file_content<P: AsRef<Path>>(file_path: P) -> Result<Vec<u8>> {
    let mut file = read_file(&file_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .map_err(|_| format!("Cannot read file {:?}", file_path.as_ref()))?;
    Ok(data)
}

pub fn create_file<P: AsRef<Path>>(file_path: P) -> Result<File> {
    let file_path = file_path.as_ref();
    if let Some(parent) = file_path.parent() {
        create_directory(parent)?;
        Ok(File::create(&file_path)
           .map_err(|_| format!("Cannot create file {:?}", file_path))?)
    } else {
        Err(format!("Path not valid {:?}", file_path))
    }
}
