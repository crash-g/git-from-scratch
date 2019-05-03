use std::{
    fs,
    io::{prelude::*, Error, ErrorKind},
    path::{Path, PathBuf},
    result::Result::Err,
    collections::BTreeMap,
};
use flate2::{
    Compression,
    read::{ZlibDecoder},
    write::{ZlibEncoder},
};

use ini::Ini;
use either::Either;

type Result<T> = std::result::Result<T, Error>;
pub type Sha1 = String;

const CONFIG_INI: &str = "config";
const GIT_PRIVATE_FOLDER: &str = ".git";

///////////////////// structures and traits ///////////////////////

pub struct GitRepository {
    worktree: PathBuf,
    gitdir: PathBuf,
    conf: Option<Ini>,
}

pub enum GitObject<'a> {
    Blob {
        repository: &'a GitRepository,
        data: Vec<u8>,
    }
}

//////// implementations ////////

impl GitRepository {
    fn new<P: AsRef<Path>>(path: P, force: bool) -> Result<Self> {
        let worktree = path.as_ref().to_path_buf();
        let gitdir = path.as_ref().join(GIT_PRIVATE_FOLDER);

        if !force && !gitdir.is_dir() {
            return Err(Error::new(ErrorKind::InvalidInput, format!("Not a Git repository {:?}", gitdir)));
        }

        let conf = Ini::load_from_file(gitdir.join(CONFIG_INI));
        let conf = match conf {
            Err(_) => {
                if !force {
                    return Err(Error::new(ErrorKind::NotFound, format!("Configuration file is missing")));
                } else {
                    None
                }
            }
            Ok(x) => Some(x)
        };

        if force {
            Ok(Self{worktree, gitdir, conf})
        } else {
            let vers: Option<i32> = conf.as_ref().and_then(|c| c.section(Some("core")))
                .and_then(|properties| properties.get("repositoryformatversion"))
                .and_then(|v| v.parse().ok());

            match vers {
                Some(0) => Ok(Self{worktree, gitdir, conf}),
                _ => Err(Error::new(ErrorKind::InvalidData, "Unsupported repositoryformatversion"))
            }
        }
    }
}

impl<'a> GitObject<'a> {
    const BLOB_FMT: &'static [u8] = b"blob";

    fn new_blob(repository: &GitRepository, data: Vec<u8>) -> GitObject {
        GitObject::Blob{repository, data}
    }

    fn serialize(&self) -> Vec<u8> {
        use GitObject::*;
        match self {
            Blob{repository: _, data} => data.to_vec(),
        }
    }

    fn get_fmt(&self) -> &[u8] {
        use GitObject::*;
        match self {
            Blob{repository: _, data: _} => GitObject::BLOB_FMT,
        }
    }

    fn get_repository(&self) -> &GitRepository {
        use GitObject::*;
        match self {
            Blob{repository, data: _} => repository,
        }
    }

    fn get_data(&self) -> Either<Vec<u8>, String> {
        use GitObject::*;
        match self {
            Blob{repository: _, data} => Either::Left(data.clone()),
        }
    }
}

//////////// init //////////////

pub fn repo_create<P: AsRef<Path>>(path: P) -> Result<GitRepository> {
    let repo = GitRepository::new(path, true)?;

    if repo.worktree.exists() {
        if !repo.worktree.is_dir() {
            return Err(Error::new(
                ErrorKind::InvalidInput, format!("{:?} is not a directory", repo.worktree)
            ));
        }
        let content = repo.worktree.read_dir()?;
        if let Some(_) = content.into_iter().next() {
            return Err(Error::new(
                ErrorKind::InvalidInput, format!("{:?} is not empty", repo.worktree)
            ));
        }
    }

    repo_dir(&repo, &["branches"], true)?;
    repo_dir(&repo, &["objects"], true)?;
    repo_dir(&repo, &["refs", "tags"], true)?;
    repo_dir(&repo, &["refs", "heads"], true)?;

    let mut description_file = fs::File::create(
        repo_file(&repo, &["description"], true)?
    )?;
    description_file.write_all(
        b"Unnamed repository; edit this file 'description' to name the repository.\n"
    )?;

    let mut head_file = fs::File::create(
        repo_file(&repo, &["HEAD"], true)?
    )?;
    head_file.write_all(b"ref: refs/heads/master\n")?;

    let config = repo_default_config();
    config.write_to_file(repo_file(&repo, &[CONFIG_INI], true)?)?;

    Ok(repo)
}

fn repo_default_config() -> Ini {
    let mut conf = Ini::new();
    conf.with_section(Some("core".to_owned()))
        .set("repositoryformatversion", "0")
        .set("filemode", "false")
        .set("bare", "false");
    conf
}

//////////// cat-file //////////////

pub fn cat_file<P: AsRef<Path>>(current_directory: P, fmt: &str, sha: &Sha1) -> Result<Either<Vec<u8>,String>> {
    let repository = repo_find_required(current_directory)?;
    let sha = object_find(&repository, sha, Some(fmt));
    let git_object = object_read(&repository, sha)?;
    Ok(git_object.get_data())
}

//////////// hash-object //////////////

pub fn hash_object<P: AsRef<Path>>(file_path: P, fmt: &str, actually_write: bool) -> Result<Sha1> {
    let repository = repo_find_required(&file_path)?;
    let mut file = fs::File::open(&file_path)?;
    let mut data: Vec<u8> = Vec::new();
    file.read_to_end(&mut data)?;

    if fmt.as_bytes() == GitObject::BLOB_FMT {
        let object = GitObject::new_blob(&repository, data);
        object_write(&object, actually_write)
    } else {
        Err(Error::new(ErrorKind::InvalidData, "TODO"))
    }
}

//////////// read/write //////////////

fn object_find<'a>(repo: &GitRepository, sha: &'a Sha1, fmt: Option<&str>) -> &'a Sha1 {
    sha
}

fn object_read<'a>(repo: &'a GitRepository, sha: &Sha1) -> Result<GitObject<'a>> {
    let path = repo_file(&repo, &["objects", &sha[0..2], &sha[2..]], false)?;
    let file = fs::File::open(&path)?;
    let mut zlib_decoder = ZlibDecoder::new(&file);
    let mut contents = Vec::new();
    zlib_decoder.read_to_end(&mut contents)?;

    let space_position = contents.iter().position(|b| *b == b' ');
    let null_position = contents.iter().position(|b| *b == b'\x00');

    match (space_position, null_position) {
        (None, _) => Err(Error::new(ErrorKind::InvalidData, "TODO")),
        (_, None) => Err(Error::new(ErrorKind::InvalidData, "TODO")),
        (Some(sp), Some(np)) if np < sp => Err(Error::new(ErrorKind::InvalidData, "TODO")),
        (Some(sp), Some(np)) => {
            let fmt = &contents[0..sp];
            let size: usize = std::str::from_utf8(&contents[sp+1..np])
                .map_err(|_| Error::new(ErrorKind::InvalidData, "TODO"))?
                .parse()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "TODO"))?;
            if size != contents.len() - np - 1 {
                Err(Error::new(ErrorKind::InvalidData, "TODO"))
            } else {
                if fmt == GitObject::BLOB_FMT {
                    Ok(GitObject::new_blob(repo, contents[np+1..].to_vec()))
                } else {
                    Err(Error::new(ErrorKind::InvalidData, "TODO other fmt"))
                }
            }
        }
    }
}

fn object_write(object: &GitObject, actually_write: bool) -> Result<Sha1> {
    let data = object.serialize();

    let mut result = object.get_fmt().to_vec();
    result.extend_from_slice(b" ");
    result.extend_from_slice(data.len().to_string().as_bytes());
    result.extend_from_slice(b"\x00");
    result.extend(data);

    let sha = sha1::Sha1::from(&result).hexdigest();

    if actually_write {
        let path = repo_file(object.get_repository(), &["objects", &sha[0..2], &sha[2..]], true)?;
        let file = fs::OpenOptions::new().write(true)
            .create_new(true)
            .open(&path)?;

        let mut zlib_encoder = ZlibEncoder::new(file, Compression::default());
        zlib_encoder.write_all(&result)?;
        zlib_encoder.finish()?;
    }
    Ok(sha)
}

#[test]
fn test_blob_write_read() -> Result<()> {
    let base_path = Path::new("/home/crash/Desktop/Progetti/Rust/git-from-scratch/target/test");
    if base_path.exists() {
        fs::remove_dir_all(base_path)?;
    }

    let test_path = base_path.join("blob");
    let repository = repo_create(&test_path)?;
    let git_blob = GitObject::new_blob(&repository, b"100".to_vec());

    let sha = object_write(&git_blob, true)?;
    let git_object = object_read(&repository, &sha)?;

    use GitObject::*;
    match git_object {
        Blob{repository: _, data} => assert_eq!(b"100".to_vec(), data)
    }
    Ok(())
}

//////////// parse key-value list with message //////////////

fn parse_kvlm(raw: &[u8], dict: &mut BTreeMap<&str, Vec<u8>>) -> Result<()> {
    let space_position = raw.iter().position(|b| *b == b' ');
    let newline_position = raw.iter().position(|b| *b == b'\n');

    match (space_position, newline_position) {
        (None, Some(np)) if np == 0 => {
            dict.insert("", raw[1..].to_vec());
            Ok(())
        }
        (Some(sp), Some(np)) if np < sp => {
            dict.insert("", raw[1..].to_vec());
            Ok(())
        }
        (Some(sp), Some(np)) => {
            let key = &raw[0..sp];
            let value = parse_value(&raw[sp+1..]);
            // TODO
            Ok(())
        }
        _ => Err(Error::new(ErrorKind::InvalidData, "TODO: Is this an error??"))
    }
}

fn parse_value(raw: &[u8]) -> &[u8] {
    let mut iterator = raw.iter();
    while let Some(np) = iterator.position(|b| *b == b'\n') {
        if raw.len() <= np || raw[np] != b' ' {
            return &raw[..np];
        }
    }
    raw
}

fn replace<T>(source: &[T], from: &[T], to: &[T]) -> Vec<T>
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

//////////// utility functions //////////////

fn repo_path<P: AsRef<Path>>(repo: &GitRepository, path: &[P]) -> PathBuf {
    let mut repo_path = repo.gitdir.clone();
    for p in path {
        repo_path = repo_path.join(p);
    }
    repo_path
}

fn repo_dir<P: AsRef<Path>>(repo: &GitRepository, path: &[P], mkdir: bool) -> Result<PathBuf> {
    let repo_path = repo_path(repo, path);

    if repo_path.exists() {
        if repo_path.is_dir() {
            return Ok(repo_path);
        } else {
            return Err(Error::new(ErrorKind::InvalidInput, format!("{:?} is not a directory", repo_path)));
        }
    }

    if mkdir {
        println!("Creating path {:?}", repo_path);
        fs::create_dir_all(&repo_path)?;
        Ok(repo_path)
    } else {
        Err(Error::new(ErrorKind::NotFound, format!("The repository path {:?} does not exist", repo_path)))
    }
}

fn repo_file<P: AsRef<Path>>(repo: &GitRepository, path: &[P], mkdir: bool) -> Result<PathBuf> {
    repo_dir(repo, &path[..path.len()-1], mkdir)?;
    Ok(repo_path(repo, path))
}

fn repo_find<P: AsRef<Path>>(path: P) -> Result<Option<GitRepository>> {
    for ancestor in path.as_ref().ancestors() {
        println!("Checking {:?}", ancestor);
        if ancestor.join(GIT_PRIVATE_FOLDER).is_dir() {
            println!("Found .git in {:?}", ancestor);
            return Ok(Some(GitRepository::new(ancestor, false)?));
        }
    }
    Ok(None)
}

fn repo_find_required<P: AsRef<Path>>(path: P) -> Result<GitRepository> {
    if let Some(repo) = repo_find(&path)? {
        Ok(repo)
    } else {
        Err(Error::new(ErrorKind::NotFound, format!("{:?} is not a valid Git repository", path.as_ref())))
    }
}

#[test]
fn test_repo_find() {
    let path = Path::new("/home/crash/bad/path");
    let repo = repo_find(path);
    assert!(repo.is_ok());
    assert!(repo.unwrap().is_none());
}
