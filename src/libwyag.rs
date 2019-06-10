use std::{
    str::from_utf8,
    io::prelude::*,
    path::{Path, PathBuf},
    result::Result::Err,
    collections::HashSet,
};

use linked_hash_map::LinkedHashMap;
use regex::Regex;

pub type Result<T> = std::result::Result<T, String>;
pub type Sha1 = String;

const CONFIG_INI: &str = "config";
const GIT_PRIVATE_FOLDER: &str = ".git";

mod utils;
use utils::*;

mod data_structures;
use data_structures::*;

//////////// init //////////////

pub fn init<P: AsRef<Path>>(path: P) -> Result<()> {
    GitRepository::create(path)?;
    Ok(())
}

//////////// cat-file //////////////

pub fn cat_file(repository: &GitRepository, fmt: &str, sha: &Sha1) -> Result<Vec<u8>> {
    let sha = find_object_of_type(&repository, &sha, fmt, false)?;
    let git_object = GitObject::read(&repository, &sha)?;
    Ok(git_object.serialize())
}

//////////// hash-object //////////////

pub fn hash_object<P: AsRef<Path>>(file_path: P, fmt: &str, actually_write: bool) -> Result<Sha1> {
    let repository = find_repository_required(&file_path)?;
    let data = read_file_content(repository.gitdir().join(file_path))?;
    let object = GitObject::new(fmt.as_bytes(), &data)?;
    if actually_write {
        object.write(&repository)
    } else {
        Ok(object.hash())
    }
}

//////////// log //////////////

pub fn log<P: AsRef<Path>>(file_path: P, sha: &Sha1) -> Result<String> {
    let repository = find_repository_required(&file_path)?;
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

pub fn ls_tree(repository: &GitRepository, sha: &Sha1) -> Result<String> {
    let sha = find_object(&repository, &sha)?;
    let tree = GitObject::read(&repository, &sha)?;

    match tree {
        GitObject::Tree{data} => {
            let mut result = String::new();
            for leaf in data.get_leaves() {
                let fmt = GitObject::read(repository, leaf.sha())?.get_fmt();
                let fmt = from_utf8(fmt).expect(&format!("fmt should be utf8: {:?}", fmt));
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

pub fn checkout_tree<P: AsRef<Path>>(repository: &GitRepository, sha: &Sha1, path: P) -> Result<()> {
    let sha = find_object(&repository, &sha)?;
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

fn checkout_tree_impl<P: AsRef<Path>>(repository: &GitRepository,
                                      tree: &Tree,
                                      path: P) -> Result<()> {
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
            _ => return Err("This tree contains an object which is neither a tree or a blob".to_string()),
        }
    }
    Ok(())
}

//////////// show references //////////////

pub fn show_references<P: AsRef<Path>>(repository: &GitRepository, custom_full_path: Option<P>) -> Result<()> {
    let references = list_references(&repository, custom_full_path)?;
    for (path, hash) in references {
        println!("{:?} -> {}", path, hash);
    }
    Ok(())
}

//////////// tag //////////////

/// Create a "lightweight" reference to a commit, tree or blob
pub fn create_tag(repository: &GitRepository, name: &str, reference: &Sha1) -> Result<()> {
    let sha = find_object(&repository, reference)?;
    create_reference(&repository, Path::new("tags").join(name), &sha)?;
    Ok(())
}

/// Create a full-fledged tag object
pub fn create_tag_object(repository: &GitRepository, name: &str, reference: &Sha1) -> Result<()> {
    let sha = find_object(&repository, reference)?;

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

//////////// read/write/search //////////////

pub fn find_object_of_type(repository: &GitRepository, sha: &Sha1, fmt: &str, follow: bool) -> Result<Sha1> {
    let sha = resolve_object(repository, sha)?;

    let object = GitObject::read(repository, &sha)?;
    if object.get_fmt() == fmt.as_bytes() {
        return Ok(sha);
    } else if !follow {
        return Err(format!("{} does not have type {}", sha, fmt));
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

    find_object_of_type(repository, &sha.to_string(), fmt, true)
}

fn find_object(repository: &GitRepository, sha: &Sha1) -> Result<Sha1> {
    resolve_object(repository, sha)
}

fn resolve_object(repository: &GitRepository, name: &str) -> Result<Sha1> {
    lazy_static! {
        static ref HASH_RE: Regex = Regex::new(r"^[0-9A-Fa-f]{4,40}$")
            .expect("Cannot compile HASH_RE regex");
    }

    if name == "HEAD" {
        return resolve_reference(repository, name);
    }

    if HASH_RE.is_match(name) {
        if name.len() == 40 {
            return Ok(name.to_lowercase());
        }
        let name = name.to_lowercase();
        let paths = read_directory_content(repository.gitdir().join("objects").join(&name[..2]))
            .map_err(|_| format!("{} is not a valid short hash", name));
        let candidates: Vec<String> = paths?.iter()
            .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with(&name[2..]))
            .map(|p| name[..2].to_string() + p.file_name().unwrap().to_string_lossy().as_ref()).collect();
        if candidates.len() == 1 {
            return Ok(candidates[0].clone());
        } else if candidates.len() > 1 {
            return Err(format!("Found {} candidates for {}", candidates.len(), name));
        }
    }
    Err(format!("{} cannot be resolved to a hash", name))
}

//////////// references //////////////

// A reference is either
// - indirect: a path to a file prepended by 'ref:',
// - direct: the hash of a Git Object
//
// Examples of references are branches and lightweight tags.
// Also, note that HEAD is always an indirect reference to a branch, unless
// Git is in detached HEAD state, in which case it is a direct reference to a commit

fn list_references<P: AsRef<Path>>(repository: &GitRepository, custom_full_path: Option<P>) -> Result<LinkedHashMap<PathBuf, Sha1>> {
    let path = if let Some(p) = custom_full_path {
        p.as_ref().to_path_buf()
    } else {
        repository.gitdir().join("refs")
    };

    let mut results = LinkedHashMap::new();
    let mut directory_content = read_directory_content(path)?;
    directory_content.sort_unstable();
    for entry in directory_content {
        if entry.is_dir() {
            for nested_reference in list_references(repository, Some(entry))? {
                results.insert(nested_reference.0, nested_reference.1);
            }
        } else {
            let reference = resolve_reference(repository, &entry)?;
            results.insert(entry, reference);
        }
    }
    Ok(results)
}

fn resolve_reference<P: AsRef<Path>>(repository: &GitRepository, reference: P) -> Result<Sha1> {
    let path = repository.gitdir().join(&reference);
    let data = read_file_content(path)?;
    let reference_value = from_utf8(&data)
        .map_err(|_| format!("The reference {:?} does not contain valid UTF-8", reference.as_ref()))?;
    let reference_prefix = "ref: ";
    if reference_value.starts_with(reference_prefix) {
        resolve_reference(repository, reference_value[reference_prefix.len()..].trim())
    } else {
        Ok(reference_value.to_string())
    }
}

fn create_reference<P: AsRef<Path>>(repository: &GitRepository, reference: P, sha: &Sha1) -> Result<()> {
    let path = repository.gitdir().join("refs").join(reference);
    let mut file = create_file(&path)?;
    let mut sha = sha.clone();
    sha.push('\n');
    file.write_all(sha.as_bytes())
        .map_err(|_| format!("Cannot write to reference file {:?}", path))?;
    Ok(())
}

/// Recursively look for a `.git` directory in the current directory
/// or in one of its parents.
pub fn find_repository<P: AsRef<Path>>(path: P) -> Option<Result<GitRepository>> {
    for ancestor in path.as_ref().ancestors() {
        println!("Checking {:?}", ancestor);
        if ancestor.join(GIT_PRIVATE_FOLDER).is_dir() {
            println!("Found .git in {:?}", ancestor);
            return Some(GitRepository::read(ancestor));
        }
    }
    None
}

#[test]
fn test_find_repository() {
    let path = Path::new("/home/user/bad/path");
    let repo = find_repository(path);
    assert!(repo.is_none());
}

/// Recursively look for a `.git` directory in the current directory
/// or in one of its parents. If it does not one, raise an error.
pub fn find_repository_required<P: AsRef<Path>>(path: P) -> Result<GitRepository> {
    find_repository(&path).ok_or(format!("Repository not found in {:?}", path.as_ref()))?
}
