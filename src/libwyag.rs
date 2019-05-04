use std::{
    fs,
    fs::File,
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
    fn new_unsafe<P: AsRef<Path>>(path: P) -> Self {
        let worktree = path.as_ref().to_path_buf();
        let gitdir = path.as_ref().join(GIT_PRIVATE_FOLDER);
        let conf = Ini::load_from_file(gitdir.join(CONFIG_INI)).ok();
        Self{worktree, gitdir, conf}
    }

    fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let worktree = path.as_ref().to_path_buf();
        let gitdir = path.as_ref().join(GIT_PRIVATE_FOLDER);

        if !gitdir.is_dir() {
            return Err(Error::new(ErrorKind::InvalidInput, format!("Not a Git repository {:?}", gitdir)));
        }

        let conf = Ini::load_from_file(gitdir.join(CONFIG_INI))
            .map_err(|_| Error::new(ErrorKind::NotFound, "Configuration file is missing"))?;

        let vers: Option<i32> = conf.section(Some("core"))
            .and_then(|properties| properties.get("repositoryformatversion"))
            .and_then(|v| v.parse().ok());

        match vers {
            Some(0) => Ok(Self{worktree, gitdir, conf: Some(conf)}),
            _ => Err(Error::new(ErrorKind::InvalidData, "Unsupported repositoryformatversion"))
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
            Blob{..} => GitObject::BLOB_FMT,
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

pub fn create_repository<P: AsRef<Path>>(path: P) -> Result<GitRepository> {
    let repo = GitRepository::new_unsafe(path);

    if repo.worktree.exists() {
        if !repo.worktree.is_dir() {
            return Err(Error::new(
                ErrorKind::InvalidInput, format!("{:?} is not a directory", repo.worktree)
            ));
        }
        let content = repo.worktree.read_dir()
            .map_err(|e| Error::new(e.kind(), format!("Cannot read the content of {:?}", repo.worktree)))?;
        if let Some(_) = content.into_iter().next() {
            return Err(Error::new(
                ErrorKind::InvalidInput, format!("{:?} is not empty", repo.worktree)
            ));
        }
    }

    create_directory(&repo, &["branches"])?;
    create_directory(&repo, &["objects"])?;
    create_directory(&repo, &["refs", "tags"])?;
    create_directory(&repo, &["refs", "heads"])?;

    let mut description_file = create_file(&repo, &["description"])?;
    description_file.write_all(
        b"Unnamed repository; edit this file 'description' to name the repository.\n"
    ).map_err(|e| Error::new(e.kind(), "Cannot write to description file"))?;

    let mut head_file = create_file(&repo, &["HEAD"])?;
    head_file.write_all(b"ref: refs/heads/master\n")
        .map_err(|e| Error::new(e.kind(), "Cannot write to HEAD file"))?;

    let config = repo_default_config();
    config.write_to_file(get_absolute_path(&repo, &[CONFIG_INI]))
        .map_err(|e| Error::new(e.kind(), "Cannot write to config file"))?;

    Ok(repo)
}

fn repo_default_config() -> Ini {
    let mut conf = Ini::new();
    conf.with_section(Some("core".to_string()))
        .set("repositoryformatversion", "0")
        .set("filemode", "false")
        .set("bare", "false");
    conf
}

//////////// cat-file //////////////

pub fn cat_file<P: AsRef<Path>>(current_directory: P, fmt: &str, sha: &Sha1) -> Result<Either<Vec<u8>,String>> {
    let repository = find_repository_required(current_directory)?;
    let sha = find_object(&repository, sha, Some(fmt));
    let git_object = read_object(&repository, sha)?;
    Ok(git_object.get_data())
}

//////////// hash-object //////////////

pub fn hash_object<P: AsRef<Path>>(file_path: P, fmt: &str, actually_write: bool) -> Result<Sha1> {
    if fmt.as_bytes() == GitObject::BLOB_FMT {
        let repository = find_repository_required(&file_path)?;
        let data = read_file_content(&repository, file_path)?;
        let object = GitObject::new_blob(&repository, data);
        object_write(&object, actually_write)
    } else {
        Err(Error::new(ErrorKind::InvalidData, format!("Object format {} not supported", fmt)))
    }
}

//////////// read/write //////////////

fn find_object<'a>(repo: &GitRepository, sha: &'a Sha1, fmt: Option<&str>) -> &'a Sha1 {
    sha
}

fn read_object<'a>(repository: &'a GitRepository, sha: &Sha1) -> Result<GitObject<'a>> {
    let file = read_file(&repository, &["objects", &sha[0..2], &sha[2..]])?;
    let mut zlib_decoder = ZlibDecoder::new(&file);
    let mut contents = Vec::new();
    zlib_decoder.read_to_end(&mut contents)
        .map_err(|e| Error::new(e.kind(), format!("Cannot decode content of object with hash {}", sha)))?;

    let space_position = contents.iter().position(|b| *b == b' ');
    let null_position = contents.iter().position(|b| *b == b'\x00');

    match (space_position, null_position) {
        (Some(sp), Some(np)) if np > sp => {
            let fmt = &contents[0..sp];
            let size: usize = std::str::from_utf8(&contents[sp+1..np])
                .map_err(|_| Error::new(ErrorKind::InvalidData, "UTF-8 required"))?
                .parse()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "Size must be an integer"))?;
            if size != contents.len() - np - 1 {
                Err(Error::new(ErrorKind::InvalidData,
                               format!("The size of the object differs from the declared size, which is {}", size)))
            } else {
                if fmt == GitObject::BLOB_FMT {
                    Ok(GitObject::new_blob(repository, contents[np+1..].to_vec()))
                } else {
                    Err(Error::new(ErrorKind::InvalidData, format!("Object format {:?} not supported", fmt)))
                }
            }
        }
        _ => Err(Error::new(ErrorKind::InvalidData, format!("Bad format for object with hash {}", sha)))
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
        let file = create_file(object.get_repository(), &["objects", &sha[0..2], &sha[2..]])?;
        let mut zlib_encoder = ZlibEncoder::new(file, Compression::default());
        zlib_encoder.write_all(&result).map_err(|e| Error::new(e.kind(), "Cannot encode object content"))?;
        zlib_encoder.finish().map_err(|e| Error::new(e.kind(), "Cannot finilize object write"))?;
    }
    Ok(sha)
}

#[test]
fn test_blob_write_read() -> Result<()> {
    let base_path = Path::new("~/Desktop/Progetti/Rust/git-from-scratch/target/test");
    if base_path.exists() {
        fs::remove_dir_all(base_path)?;
    }

    let test_path = base_path.join("blob");
    let repository = create_repository(&test_path)?;
    let git_blob = GitObject::new_blob(&repository, b"100".to_vec());

    let sha = object_write(&git_blob, true)?;
    let git_object = read_object(&repository, &sha)?;

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

fn get_absolute_path<P: AsRef<Path>>(repo: &GitRepository, path: &[P]) -> PathBuf {
    let mut absolute_path = repo.gitdir.clone();
    for p in path {
        absolute_path = absolute_path.join(p);
    }
    absolute_path
}

fn create_directory<P: AsRef<Path>>(repo: &GitRepository, path: &[P]) -> Result<PathBuf> {
    let directory_path = get_absolute_path(repo, path);

    if directory_path.exists() {
        if directory_path.is_dir() {
            return Ok(directory_path);
        } else {
            return Err(Error::new(ErrorKind::InvalidInput, format!("{:?} is not a directory", directory_path)));
        }
    }

    println!("Creating directory {:?}", directory_path);
    fs::create_dir_all(&directory_path)
        .map_err(|e| Error::new(e.kind(), format!("Cannot create {:?} directory", directory_path)))?;
    Ok(directory_path)
}

fn read_file<P: AsRef<Path>>(repo: &GitRepository, path: &[P]) -> Result<File> {
    let directory_path = get_absolute_path(repo, &path[..path.len()-1]);
    if directory_path.is_dir() {
        let file_path = get_absolute_path(repo, path);
        Ok(File::open(&file_path)
           .map_err(|e| Error::new(e.kind(), format!("Cannot open {:?} file", file_path)))?)
    } else {
        Err(Error::new(ErrorKind::InvalidInput, format!("{:?} is not a directory", directory_path)))
    }
}

fn read_file_content<P: AsRef<Path>>(repository: &GitRepository, file_path: P) -> Result<Vec<u8>> {
    let mut file = read_file(repository, &[&file_path])?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .map_err(|e| Error::new(e.kind(), format!("Cannot read file {:?}", file_path.as_ref())))?;
    Ok(data)
}

fn create_file<P: AsRef<Path>>(repo: &GitRepository, path: &[P]) -> Result<File> {
    create_directory(repo, &path[..path.len()-1])?;
    Ok(File::create(get_absolute_path(repo, path))?)
}

fn find_repository<P: AsRef<Path>>(path: P) -> Option<Result<GitRepository>> {
    for ancestor in path.as_ref().ancestors() {
        println!("Checking {:?}", ancestor);
        if ancestor.join(GIT_PRIVATE_FOLDER).is_dir() {
            println!("Found .git in {:?}", ancestor);
            return Some(GitRepository::new(ancestor));
        }
    }
    None
}

fn find_repository_required<P: AsRef<Path>>(path: P) -> Result<GitRepository> {
    find_repository(&path)
        .ok_or(Error::new(ErrorKind::InvalidInput,
                          format!("Repository not found in {:?}", path.as_ref())))?
}

#[test]
fn test_find_repository() {
    let path = Path::new("/home/user/bad/path");
    let repo = find_repository(path);
    assert!(repo.is_none());
}
