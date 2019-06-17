//! Implementation of the main functionalities.
//!
//! Git handles objects and references. For a description of the
//! objects, see the module `data_structures`. For a description of
//! references see the module `references`.

use std::{
    str::from_utf8,
    io::prelude::*,
    path::Path,
    result::Result::Err,
    collections::HashSet,
};

use lazy_static::lazy_static;
use regex::Regex;

pub type Result<T> = std::result::Result<T, String>;
pub type Sha1 = String;

const CONFIG_INI: &str = "config";
const GIT_PRIVATE_FOLDER: &str = ".git";

mod utils;
use utils::*;

mod data_structures;
use data_structures::*;
pub use data_structures::GitRepository;

mod references;
use references::*;

/// Initialize a repository at the given path.
pub fn init<P: AsRef<Path>>(path: P) -> Result<()> {
    GitRepository::create(path)?;
    Ok(())
}

pub fn cat_file(repository: &GitRepository, fmt: &str, sha: &Sha1) -> Result<Vec<u8>> {
    let sha = resolve_identifier_by_type(&repository, &sha, fmt)?;
    let git_object = GitObject::read(&repository, &sha)?;
    Ok(git_object.serialize())
}

pub fn hash_object<P: AsRef<Path>>(file_path: P, fmt: &str, actually_write: bool) -> Result<Sha1> {
    let repository = GitRepository::find_repository_required(&file_path)?;
    let data = read_file_content(repository.gitdir().join(file_path))?;
    let object = GitObject::new(fmt, &data)?;
    if actually_write {
        object.write(&repository)
    } else {
        Ok(object.hash())
    }
}

pub fn log<P: AsRef<Path>>(file_path: P, sha: &Sha1) -> Result<String> {
    let repository = GitRepository::find_repository_required(&file_path)?;
    let mut result = "digraph wyaglog{".to_string();
    let mut seen = HashSet::new();
    result += &make_graphviz_string(&repository, sha, &mut seen)?;
    result += "}";
    Ok(result)
}

fn make_graphviz_string(repository: &GitRepository, sha: &Sha1, seen: &mut HashSet<Sha1>) -> Result<String> {
    if !seen.insert(sha.to_string()) {
        return Ok("".to_string());
    }

    let commit = GitObject::read(repository, sha)?;
    match commit {
        GitObject::Commit{data} => {
            match data.get("parent") {
                None => Ok("".to_string()),
                Some(parents) => {
                    let mut result = String::new();
                    for p in parents {
                        let p = from_utf8(p)
                            .map_err(|_| "Parent must be valid UTF-8".to_string())?
                            .to_string();
                        result += &format!("c_{} -> c_{};", sha, p);
                        result += &make_graphviz_string(repository, &p, seen)?;
                    }
                    Ok(result)
                }
            }
        },
        _ => Err(format!("The hash {} is not relative to a commit", sha))
    }
}

//////////// ls-tree //////////////

/// Read leaves of a tree and format them in a human-readable form.
pub fn ls_tree(repository: &GitRepository, identifier: &str) -> Result<String> {
    let sha = resolve_identifier(&repository, &identifier)?;
    let tree = GitObject::read(&repository, &sha)?;

    match tree {
        GitObject::Tree{data} => {
            let mut result = String::new();
            for leaf in data.get_leaves() {
                let fmt = GitObject::read(repository, leaf.sha())?.get_fmt();
                result += &format!("{} {} {}\t{}",
                                   leaf.mode(),
                                   fmt,
                                   leaf.sha(),
                                   leaf.path());
            }
            Ok(result)
        },
        _ => Err(format!("The hash {} is not relative to a tree", sha))
    }
}

//////////// checkout tree //////////////

/// Checkout a tree with the given identifier at the given `path`.
///
/// To make things simpler, if the `path` exists must be the path of an empty directory.
pub fn checkout_tree<P: AsRef<Path>>(repository: &GitRepository, identifier: &str, path: P) -> Result<()> {
    let sha = resolve_identifier(&repository, &identifier)?;
    let object = GitObject::read(&repository, &sha)?;

    let tree = match object {
        GitObject::Tree{data} => data,
        GitObject::Commit{data} => {
            let tree_hash = match data.get("tree") {
                Some(vec) if vec.len() == 1 => {
                    from_utf8(vec.get(0).unwrap())
                        .map_err(|_| "The value of the tree hash is not valid UTF-8".to_string())?
                },
                None => return Err(format!("Tree not found for commit {}", sha)),
                _ => return Err(format!("Too many trees for commit {}", sha)),
            };
            match GitObject::read(&repository, &tree_hash.to_string())? {
                GitObject::Tree{data} => data,
                _ => return Err(format!("The commit tree has an invalid hash")),
            }
        },
        _ => return Err(format!("The hash {} does not refer to either a commit or a tree", sha)),
    };

    let path = path.as_ref();
    create_directory(path)?;
    check_is_empty(path)?;
    checkout_tree_impl(&repository, &tree, path)
}

/// In this simplified version of Git, checking out a tree means creating
/// a file for every `Blob` object and a directory
/// for every `Tree`, then descending recursively in these directories.
fn checkout_tree_impl<P: AsRef<Path>>(
    repository: &GitRepository, tree: &Tree, path: P
) -> Result<()> {

    for leaf in tree.get_leaves() {
        let object = GitObject::read(&repository, &leaf.sha())?;
        let dest = path.as_ref().join(&leaf.path());

        match object {
            GitObject::Tree{data} => {
                create_directory(&dest)?;
                checkout_tree_impl(&repository, &data, dest)?;
            },
            GitObject::Blob{data} => {
                let mut file = create_file(&dest)?;
                file.write_all(&data)
                    .map_err(|_| format!("Cannot write to file {:?}", dest))?;
            },
            _ => return Err("This tree contains an object which is neither a tree nor a blob".to_string()),
        }
    }
    Ok(())
}

//////////// show references //////////////

/// Read references at the given path and format them in a human-readable form.
pub fn show_references<P: AsRef<Path>>(
    repository: &GitRepository, custom_full_path: Option<P>
) -> Result<String> {

    let mut result = "References:\n".to_string();
    let references = list_references(&repository, custom_full_path)?;
    for (path, hash) in references {
        result += &format!("{:?} -> {}\n", path, hash);
    }
    Ok(result)
}

//////////// tag //////////////

/// Create a "lightweight" tag, which is a reference to a commit, tree or blob.
pub fn create_lightweight_tag(repository: &GitRepository, name: &str, identifier: &str) -> Result<()> {
    let sha = resolve_identifier(&repository, identifier)?;
    create_reference(&repository, Path::new("tags").join(name), &sha)?;
    Ok(())
}

/// Create a full-fledged tag object.
pub fn create_tag_object(repository: &GitRepository, name: &str, identifier: &str) -> Result<()> {
    let sha = resolve_identifier(&repository, identifier)?;

    // TODO this does not make a lot of sense...
    let tag_data = format!("object {}
type commit
tag {}
tagger unknown

This is the message and should have come from the user", sha, name);;
    let tag = GitObject::new_tag(tag_data.as_bytes())?;

    let sha = tag.write(repository)?;
    create_reference(&repository, Path::new("tags").join(name), &sha)?;
    Ok(())
}

//////////// object identifier resolution //////////////

/// Find the full hash of a Git object given its type and identifier, recursively
/// following links found in `Tag` and `Commit` objects.
///
/// > NOTE: An object identifier can be many things in Git, but we restrict ourselves
/// > to (short and long) hashes and references.
pub fn recursively_resolve_identifier_by_type(repository: &GitRepository, identifier: &str, fmt: &str) -> Result<Sha1> {
    let sha = resolve_identifier(repository, identifier)?;

    let object = GitObject::read(repository, &sha)?;
    if object.get_fmt() == fmt {
        return Ok(sha);
    }

    let parsed_element = match object {
        GitObject::Tag{data} => {
            data.get("object")
                .ok_or(format!("Cannot find 'object' section in tag {}", sha))
                .map(|section| section.get(0)
                     .expect(&format!("Section 'object' in tag {} is empty", sha)))?
                .to_vec()
        }
        GitObject::Commit{data} => {
            data.get("tree")
                .ok_or(format!("Cannot find 'tree' section in commit {}", sha))
                .map(|section| section.get(0)
                     .expect(&format!("Section 'tree' in commit {} is empty", sha)))?
                .to_vec()
        }
        _ => {
            return Err(format!("Cannot follow {} which is neither a tag nor a commit", sha));
        }
    };

    let sha = from_utf8(&parsed_element)
        .map_err(|_| format!("Sections of {} do not contain valid UTF-8", sha))?;

    recursively_resolve_identifier_by_type(repository, &sha.to_string(), fmt)
}

/// Find the full hash of a Git object given its type and identifier.
///
/// > NOTE: An object identifier can be many things in Git, but we restrict ourselves
/// > to (short and long) hashes and references.
fn resolve_identifier_by_type(repository: &GitRepository, identifier: &str, fmt: &str) -> Result<Sha1> {
    let sha = resolve_identifier(repository, identifier)?;

    let object = GitObject::read(repository, &sha)?;
    if object.get_fmt() == fmt {
        Ok(sha)
    } else {
        Err(format!("{} does not have type {}", sha, fmt))
    }
}

/// Find the full hash of a Git object given its identifier.
///
/// > NOTE: An object identifier can be many things in Git, but we restrict ourselves
/// > to (short and long) hashes and references.
fn resolve_identifier(repository: &GitRepository, identifier: &str) -> Result<Sha1> {
    lazy_static! {
        static ref HASH_RE: Regex = Regex::new(r"^[0-9A-Fa-f]{4,40}$")
            .expect("Cannot compile HASH_RE regex");
    }

    if HASH_RE.is_match(identifier) {
        if identifier.len() == 40 {
            return Ok(identifier.to_lowercase());
        }
        let identifier = identifier.to_lowercase();
        let paths = read_directory_content(repository.gitdir().join("objects").join(&identifier[..2]));
        if paths.is_ok() {
            let candidates: Vec<String> = paths.unwrap().iter()
                .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with(&identifier[2..]))
                .map(|p| identifier[..2].to_string() + p.file_name().unwrap().to_string_lossy().as_ref())
                .collect();
            if candidates.len() == 1 {
                return Ok(candidates[0].clone());
            } else if candidates.len() > 1 {
                return Err(format!("Found {} candidates for {}", candidates.len(), identifier));
            }
        }
    }

    resolve_reference(repository, identifier)
}
