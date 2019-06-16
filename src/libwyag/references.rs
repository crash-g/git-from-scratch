//! Methods to handle references to objects.
//!
//! In Git, a reference is either:
//! - indirect: a path to a file prepended by 'ref:',
//! - direct: the hash of a Git Object
//!
//! Examples of references are branches and lightweight tags.
//! Also, note that HEAD is always an indirect reference to a branch, unless
//! Git is in detached HEAD state, in which case it is a direct reference to a commit

use std::{
    str::from_utf8,
    io::prelude::*,
    path::{Path, PathBuf},
};

use linked_hash_map::LinkedHashMap;

use super::{
    Result, Sha1,
    data_structures::*,
    utils::*,
};

const REFERENCE_PREFIX: &'static str = "ref: ";

/// List all the references in the repository, or optionally
/// just the ones in the given `custom_full_path`.
pub fn list_references<P: AsRef<Path>>(
    repository: &GitRepository, custom_full_path: Option<P>
) -> Result<LinkedHashMap<PathBuf, Sha1>> {

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

/// Resolve a reference to an object given the relative path to the reference file.
pub fn resolve_reference<P: AsRef<Path>>(repository: &GitRepository, reference: P) -> Result<Sha1> {
    let path = repository.gitdir().join(&reference);
    let data = read_file_content(path)?;
    let reference_value = from_utf8(&data)
        .map_err(|_| format!("The reference {:?} does not contain valid UTF-8", reference.as_ref()))?;
    if reference_value.starts_with(REFERENCE_PREFIX) {
        resolve_reference(repository, reference_value[REFERENCE_PREFIX.len()..].trim())
    } else {
        Ok(reference_value.to_string())
    }
}

/// Create a reference to an object given its full hash.
pub fn create_reference<P: AsRef<Path>>(repository: &GitRepository, reference: P, sha: &Sha1) -> Result<()> {
    let path = repository.gitdir().join("refs").join(reference);
    let mut file = create_file(&path)?;
    let mut sha = sha.clone();
    sha.push('\n');
    file.write_all(sha.as_bytes())
        .map_err(|_| format!("Cannot write to reference file {:?}", path))?;
    Ok(())
}
