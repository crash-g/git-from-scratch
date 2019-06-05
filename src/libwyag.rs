use std::{
    str::from_utf8,
    fs,
    fs::File,
    io::prelude::*,
    path::{Path, PathBuf},
    result::Result::Err,
    collections::HashSet,
};
use flate2::{
    Compression,
    read::{ZlibDecoder},
    write::{ZlibEncoder},
};

use linked_hash_map::LinkedHashMap;
use regex::Regex;
use ini::Ini;

pub type Result<T> = std::result::Result<T, String>;
pub type Sha1 = String;

const CONFIG_INI: &str = "config";
const GIT_PRIVATE_FOLDER: &str = ".git";

///////////////////// structures and traits ///////////////////////

pub struct GitRepository {
    worktree: PathBuf,
    gitdir: PathBuf,
    conf: Ini,
}

pub enum GitObject<'a> {
    Blob {
        repository: &'a GitRepository,
        data: Vec<u8>,
    },
    Commit {
        repository: &'a GitRepository,
        data: LinkedHashMap<String, Vec<Vec<u8>>>,
    },
    Tree {
        repository: &'a GitRepository,
        data: Vec<GitTreeLeaf>,
    },
    Tag {
        repository: &'a GitRepository,
        data: LinkedHashMap<String, Vec<Vec<u8>>>,
    },
}

#[derive(Debug)]
pub struct GitTreeLeaf {
    mode: u32,
    path: String,
    sha: Sha1,
}

//////// implementations ////////

impl GitRepository {
    fn read<P: AsRef<Path>>(path: P) -> Result<Self> {
        let worktree = path.as_ref().to_path_buf();
        let gitdir = path.as_ref().join(GIT_PRIVATE_FOLDER);

        if !gitdir.is_dir() {
            return Err(format!("Not a Git repository {:?}", gitdir));
        }

        let conf = Ini::load_from_file(gitdir.join(CONFIG_INI))
            .map_err(|_| "Configuration file is missing")?;

        let vers: Option<i32> = conf.section(Some("core"))
            .and_then(|properties| properties.get("repositoryformatversion"))
            .and_then(|v| v.parse().ok());

        match vers {
            Some(0) => Ok(Self{worktree, gitdir, conf: conf}),
            _ => Err("Unsupported repositoryformatversion".to_string())
        }
    }

    pub fn gitdir(&self) -> &Path {
        &self.gitdir
    }
}

impl<'a> GitObject<'a> {
    const BLOB_FMT: &'static [u8] = b"blob";
    const COMMIT_FMT: &'static [u8] = b"commit";
    const TREE_FMT: &'static [u8] = b"tree";
    const TAG_FMT: &'static [u8] = b"tag";

    fn new(fmt: &[u8], repository: &'a GitRepository, data: &[u8])
           -> Result<GitObject<'a>> {
        if fmt == GitObject::BLOB_FMT {
            Ok(GitObject::new_blob(repository, data.to_vec()))
        } else if fmt == GitObject::COMMIT_FMT {
            GitObject::new_commit(repository, data)
        } else if fmt == GitObject::TREE_FMT {
            GitObject::new_tree(repository, data)
        } else if fmt == GitObject::TAG_FMT {
            GitObject::new_tag(repository, data)
        } else {
            Err(format!("The format {} is not supported",
                        from_utf8(fmt).expect("fmt should be UTF-8")))
        }
    }

    fn new_blob(repository: &GitRepository, data: Vec<u8>) -> GitObject {
        GitObject::Blob{repository, data}
    }

    fn new_commit(repository: &'a GitRepository, data: &[u8]) -> Result<GitObject<'a>> {
        let mut dict = LinkedHashMap::new();
        parse_kvlm(&data, &mut dict)?;
        Ok(GitObject::Commit{repository, data: dict})
    }

    fn new_tree(repository: &'a GitRepository, data: &[u8]) -> Result<GitObject<'a>> {
        let tree = parse_tree(&data)?;
        Ok(GitObject::Tree{repository, data: tree})
    }

    fn new_tag(repository: &'a GitRepository, data: &[u8]) -> Result<GitObject<'a>> {
        let mut dict = LinkedHashMap::new();
        parse_kvlm(&data, &mut dict)?;
        Ok(GitObject::Tag{repository, data: dict})
    }

    fn serialize(&self) -> Vec<u8> {
        use GitObject::*;
        match self {
            Blob{repository: _, data} => data.to_vec(),
            Commit{repository: _, data} => serialize_kvlm(&data),
            Tree{repository: _, data} => serialize_tree(&data),
            Tag{repository: _, data} => serialize_kvlm(&data),
        }
    }

    fn get_fmt(&self) -> &'static [u8] {
        use GitObject::*;
        match self {
            Blob{..} => GitObject::BLOB_FMT,
            Commit{..} => GitObject::COMMIT_FMT,
            Tree{..} => GitObject::TREE_FMT,
            Tag{..} => GitObject::TAG_FMT,
        }
    }

    fn get_repository(&self) -> &GitRepository {
        use GitObject::*;
        match self {
            Blob{repository, data: _} => repository,
            Commit{repository, data: _} => repository,
            Tree{repository, data: _} => repository,
            Tag{repository, data: _} => repository,
        }
    }
}

//////////// init //////////////

pub fn create_repository<P: AsRef<Path>>(path: P) -> Result<GitRepository> {
    let path = path.as_ref();
    create_directory(&path)?;
    check_is_empty(&path)?;

    let gitdir = path.join(GIT_PRIVATE_FOLDER);

    create_directory(gitdir.join("branches"))?;
    create_directory(gitdir.join("objects"))?;
    create_directory(gitdir.join("refs").join("tags"))?;
    create_directory(gitdir.join("refs").join("heads"))?;

    let mut description_file = create_file(gitdir.join("description"))?;
    description_file.write_all(
        b"Unnamed repository; edit this file 'description' to name the repository.\n"
    ).map_err(|_| "Cannot write to description file".to_string())?;

    let mut head_file = create_file(gitdir.join("HEAD"))?;
    head_file.write_all(b"ref: refs/heads/master\n")
        .map_err(|_| "Cannot write to HEAD file".to_string())?;

    let conf = repo_default_config();
    conf.write_to_file(gitdir.join(CONFIG_INI))
        .map_err(|_| "Cannot write to config file".to_string())?;

    Ok(GitRepository{worktree: path.to_path_buf(), gitdir, conf})
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

pub fn cat_file(repository: &GitRepository, fmt: &str, sha: &Sha1) -> Result<Vec<u8>> {
    let sha = find_object_of_type(&repository, &sha, fmt, false)?;
    let git_object = read_object(&repository, &sha)?;
    Ok(git_object.serialize())
}

//////////// hash-object //////////////

pub fn hash_object<P: AsRef<Path>>(file_path: P, fmt: &str, actually_write: bool) -> Result<Sha1> {
    let repository = find_repository_required(&file_path)?;
    let data = read_file_content(repository.gitdir.join(file_path))?;
    let object = GitObject::new(fmt.as_bytes(), &repository, &data)?;
    write_object(&object, actually_write)
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

    let commit = read_object(repository, sha)?;
    match commit {
        GitObject::Commit{repository, data} => {
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
    let tree = read_object(&repository, &sha)?;

    match tree {
        GitObject::Tree{repository, data} => {
            let mut result = String::new();
            for item in data {
                let fmt = read_object(repository, &item.sha)?.get_fmt();
                let fmt = from_utf8(fmt).expect(&format!("fmt should be utf8: {:?}", fmt));
                result += &format!("{} {} {}\t{}", item.mode, fmt, item.sha, item.path);
            }
            Ok(result)
        },
        _ => Err(format!("The hash {} is not relative to a tree", sha))
    }
}

//////////// checkout tree //////////////

pub fn checkout_tree<P: AsRef<Path>>(repository: &GitRepository, sha: &Sha1, path: P) -> Result<()> {
    let sha = find_object(&repository, &sha)?;
    let object = read_object(&repository, &sha)?;

    let tree_data = match object {
        GitObject::Tree{repository: _, data} => data,
        GitObject::Commit{repository: _, data} => {
            let tree_hash = match data.get("tree") {
                Some(vec) if vec.len() == 1 => {
                    from_utf8(vec.get(0).unwrap())
                        .map_err(|_| "The value of the tree hash is not valid UTF-8".to_string())?
                },
                None => return Err(format!("Tree not found for commit {}", sha)),
                _ => return Err(format!("Too many trees for commit {}", sha)),
            };
            match read_object(&repository, &tree_hash.to_string())? {
                GitObject::Tree{repository: _, data} => data,
                _ => return Err(format!("The commit tree has an invalid hash")),
            }
        },
        _ => return Err(format!("The hash {} does not refer to either a commit or a tree", sha)),
    };

    let path = path.as_ref();
    create_directory(path)?;
    check_is_empty(path)?;
    checkout_tree_impl(&repository, &tree_data, path)
}

fn checkout_tree_impl<P: AsRef<Path>>(repository: &GitRepository,
                                      tree: &Vec<GitTreeLeaf>,
                                      path: P) -> Result<()> {
    for leaf in tree {
        let object = read_object(&repository, &leaf.sha)?;
        let dest = path.as_ref().join(&leaf.path);

        match object {
            GitObject::Tree{repository: _, data} => {
                create_directory(&dest)?;
                checkout_tree_impl(&repository, &data, dest)?;
            },
            GitObject::Blob{repository: _, data} => {
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
    let tag = GitObject::new_tag(&repository, tag_data.as_bytes())?;

    let sha = write_object(&tag, true)?;
    create_reference(&repository, Path::new("tags").join(name), &sha)?;
    Ok(())
}

//////////// read/write/search //////////////

pub fn find_object_of_type(repository: &GitRepository, sha: &Sha1, fmt: &str, follow: bool) -> Result<Sha1> {
    let sha = resolve_object(repository, sha)?;

    let object = read_object(repository, &sha)?;
    if object.get_fmt() == fmt.as_bytes() {
        return Ok(sha);
    } else if !follow {
        return Err(format!("{} does not have type {}", sha, fmt));
    }

    let parsed_element = match object {
        GitObject::Tag{repository: _, data} => {
            data.get("object")
                .ok_or(format!("Cannot find 'object' section in tag {}", sha))
                .map(|section| section.get(0)
                     .expect(&format!("Section 'object' in tag {} is empty", sha)))?
                .to_vec()
        }
        GitObject::Commit{repository: _, data} => {
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
        let paths = read_directory_content(repository.gitdir.join("objects").join(&name[..2]))
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

fn read_object<'a>(repository: &'a GitRepository, sha: &Sha1) -> Result<GitObject<'a>> {
    let file = read_file(repository.gitdir.join("objects").join(&sha[0..2]).join(&sha[2..]))?;
    let mut zlib_decoder = ZlibDecoder::new(&file);
    let mut contents = Vec::new();
    zlib_decoder.read_to_end(&mut contents)
        .map_err(|_| format!("Cannot decode content of object with hash {}", sha))?;

    let space_position = contents.iter().position(|b| *b == b' ');
    let null_position = contents.iter().position(|b| *b == b'\x00');

    match (space_position, null_position) {
        (Some(sp), Some(np)) if np > sp => {
            let fmt = &contents[0..sp];
            let size: usize = from_utf8(&contents[sp+1..np])
                .map_err(|_| "UTF-8 required".to_string())?
                .parse()
                .map_err(|_| "Size must be an integer".to_string())?;
            if size != contents.len() - np - 1 {
                Err(format!("The size of the object differs from the declared size, which is {}", size))
            } else {
                GitObject::new(fmt, repository, &contents[np+1..])
            }
        }
        _ => Err(format!("Bad format for object with hash {}", sha))
    }
}

fn write_object(object: &GitObject, actually_write: bool) -> Result<Sha1> {
    let data = object.serialize();

    let mut result = object.get_fmt().to_vec();
    result.extend_from_slice(b" ");
    result.extend_from_slice(data.len().to_string().as_bytes());
    result.extend_from_slice(b"\x00");
    result.extend(data);

    let sha = sha1::Sha1::from(&result).hexdigest();

    if actually_write {
        let file = create_file(object.get_repository().gitdir.join("objects").join(&sha[0..2]).join(&&sha[2..]))?;
        let mut zlib_encoder = ZlibEncoder::new(file, Compression::default());
        zlib_encoder.write_all(&result).map_err(|_| "Cannot encode object content".to_string())?;
        zlib_encoder.finish().map_err(|_| "Cannot finilize object write".to_string())?;
    }
    Ok(sha)
}

#[test]
fn test_blob_write_read() {
    let base_path = Path::new("target/test");
    if base_path.exists() {
        fs::remove_dir_all(base_path).unwrap();
    }

    let test_path = base_path.join("blob");
    let repository = create_repository(&test_path).unwrap();
    let git_blob = GitObject::new_blob(&repository, b"100".to_vec());

    let sha = write_object(&git_blob, true).unwrap();
    let git_object = read_object(&repository, &sha).unwrap();

    use GitObject::*;
    match git_object {
        Blob{repository: _, data} => assert_eq!(b"100".to_vec(), data),
        _ => assert!(false)
    }
}

//////////// key-value list with message //////////////

// TODO check if it makes sense for the hashmap to become LinkedHashMap<String, Vec<String>>

fn parse_kvlm(raw: &[u8], dict: &mut LinkedHashMap<String, Vec<Vec<u8>>>) -> Result<()> {
    let space_position = raw.iter().position(|b| *b == b' ');
    let newline_position = raw.iter().position(|b| *b == b'\n');

    match (space_position, newline_position) {
        (_, Some(np)) if np == 0 => {
            // parse message
            dict.insert("".to_string(), vec![raw[np + 1..].to_vec()]);
            Ok(())
        }
        (Some(sp), Some(_np)) => {
            let key = from_utf8(&raw[0..sp])
                .map_err(|_| "Keys must be valid UTF-8".to_string())?;
            let (value, value_end) = parse_value(&raw[sp + 1..]);
            let value = replace(value, b"\n ", b"\n");
            match dict.get_mut(key) {
                None => {
                    dict.insert(key.to_string(), vec![value]);
                }
                Some(values) => {
                    values.push(value);
                }
            }
            let next_token_start = sp + value_end + 1;
            debug_assert!(next_token_start <= raw.len());
            parse_kvlm(&raw[next_token_start..], dict)
        }
        _ => Err("The key-value list file has an incorrect structure".to_string()),
    }
}

#[test]
fn test_parse_kvlm() {
    let raw = b"tree 29ff16c9c14e2652b22f8b78bb08a5a07930c147
parent 206941306e8a8af65b66eaaaea388a7ae24d49a0
author Thibault Polge <thibault@thb.lt> 1527025023 +0200
committer Thibault Polge <thibault@thb.lt> 1527025044 +0200
gpgsig -----BEGIN PGP SIGNATURE-----
 -----END PGP SIGNATURE-----
committer another

Create first draft";

    let mut dict = LinkedHashMap::new();
    parse_kvlm(raw, &mut dict).unwrap();
    assert_eq!("29ff16c9c14e2652b22f8b78bb08a5a07930c147",
               from_utf8(&dict.get("tree").unwrap()[0]).unwrap());
    assert_eq!("206941306e8a8af65b66eaaaea388a7ae24d49a0",
               from_utf8(&dict.get("parent").unwrap()[0]).unwrap());
    assert_eq!("Thibault Polge <thibault@thb.lt> 1527025023 +0200",
               from_utf8(&dict.get("author").unwrap()[0]).unwrap());
    assert_eq!("Thibault Polge <thibault@thb.lt> 1527025044 +0200",
               from_utf8(&dict.get("committer").unwrap()[0]).unwrap());
    assert_eq!("another",
               from_utf8(&dict.get("committer").unwrap()[1]).unwrap());
    assert_eq!("-----BEGIN PGP SIGNATURE-----\n-----END PGP SIGNATURE-----",
               from_utf8(&dict.get("gpgsig").unwrap()[0]).unwrap());
    assert_eq!("Create first draft", from_utf8(&dict.get("").unwrap()[0]).unwrap());

    let raw = b"\n";
    let mut dict = LinkedHashMap::new();
    parse_kvlm(raw, &mut dict).unwrap();
    assert_eq!("", from_utf8(&dict.get("").unwrap()[0]).unwrap());

    let raw = b"";
    let mut dict = LinkedHashMap::new();
    assert!(parse_kvlm(raw, &mut dict).is_err());
}

fn serialize_kvlm(dict: &LinkedHashMap<String, Vec<Vec<u8>>>) -> Vec<u8> {
    let mut result = Vec::new();

    for key in dict.keys() {
        if key == "" {
            continue
        }
        for value in dict.get(key).unwrap() {
            result.append(&mut key.as_bytes().to_vec());
            result.push(b' ');
            result.append(&mut replace(value, b"\n", b"\n "));
            result.push(b'\n');
        }
    }
    let message = dict.get("").expect("Message not found");
    assert_eq!(1, message.len(), "There must be exactly one message");
    let message = &message[0];
    result.push(b'\n');
    result.append(&mut message.clone());
    result
}

#[test]
fn test_parse_and_serialize_kvlm() {
    let raw = b"tree 29ff16c9c14e2652b22f8b78bb08a5a07930c147
parent 206941306e8a8af65b66eaaaea388a7ae24d49a0
author Thibault Polge <thibault@thb.lt> 1527025023 +0200
committer Thibault Polge <thibault@thb.lt> 1527025044 +0200
committer another
gpgsig -----BEGIN PGP SIGNATURE-----
 -----END PGP SIGNATURE-----

Create first draft";

    let mut dict = LinkedHashMap::new();
    parse_kvlm(raw, &mut dict).unwrap();
    let serialized_raw = serialize_kvlm(&dict);
    assert_eq!(from_utf8(raw).unwrap(), from_utf8(&serialized_raw).unwrap());
}

fn parse_value(raw: &[u8]) -> (&[u8], usize) {
    let mut to_skip = 0;
    while let Some(np) = raw.iter().skip(to_skip).position(|b| *b == b'\n') {
        let np = np + to_skip;
        if np == raw.len() - 1 || raw[np + 1] != b' ' {
            return (&raw[..np], np + 1);
        }
        to_skip = np + 1;
    }
    (raw, raw.len())
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

//////////// tree objects //////////////

fn parse_tree(raw: &[u8]) -> Result<Vec<GitTreeLeaf>> {
    let mut result = Vec::new();
    let mut start = 0;
    while start < raw.len() {
        let (leaf, offset) = parse_tree_leaf(&raw[start..])?;
        result.push(leaf);
        start += offset;
    }

    Ok(result)
}

#[test]
fn test_parse_tree() {
    let raw = b"100644 .gitignore\x00\x89JD\xcc\x06j\x02te\xcd&\xd64\x94\x8dV\xd1:\xf9\xaf\
                100633 LICENSE\x00\x94\xa9\xed\x02M8Yy6\x18\x15.\xa5Y\xa1h\xbb\xcb\xb5\xe2\
                80711 README.md\x00\xba\xb4\x89\xc4\xf4`\n8\xcem\xbf\xd6R\xb9\x03\x83\xa4\xaa>E";

    let tree = parse_tree(raw).unwrap();
    assert_eq!(100644, tree[0].mode);
    assert_eq!(".gitignore", tree[0].path);
    assert_eq!("894a44cc066a027465cd26d634948d56d13af9af", tree[0].sha);

    assert_eq!(100633, tree[1].mode);
    assert_eq!("LICENSE", tree[1].path);
    assert_eq!("94a9ed024d3859793618152ea559a168bbcbb5e2", tree[1].sha);

    assert_eq!(80711, tree[2].mode);
    assert_eq!("README.md", tree[2].path);
    assert_eq!("bab489c4f4600a38ce6dbfd652b90383a4aa3e45", tree[2].sha);
}

fn parse_tree_leaf(raw: &[u8]) -> Result<(GitTreeLeaf, usize)> {
    let space_position = raw.iter().position(|b| *b == b' ');
    let null_position = raw.iter().position(|b| *b == b'\x00');

    match (space_position, null_position) {
        (Some(sp), Some(np))
            if sp < np &&
            (sp == 5 || sp == 6) &&
            np + 20 < raw.len() =>
        {
            let mode: u32 = from_utf8(&raw[..sp])
                .map_err(|_| "Mode must be valid UTF-8".to_string())?
                .parse()
                .map_err(|_| "Mode must be a valid ASCII number".to_string())?;
            let path = from_utf8(&raw[sp + 1..np])
                .map_err(|_| "Path must be valid UTF-8".to_string())?.to_string();
            let sha = hex::encode(&raw[np + 1..np + 21]);
            Ok((GitTreeLeaf{mode, path, sha}, np+21))
        }
        _ => Err(format!("Cannot parse tree: {}", from_utf8(raw).expect("The tree should be valid UTF-8")))
    }
}

fn serialize_tree(tree: &Vec<GitTreeLeaf>) -> Vec<u8> {
    let mut result = Vec::new();

    for GitTreeLeaf{mode, path, sha} in tree {
        result.append(&mut mode.to_string().as_bytes().to_vec());
        result.push(b' ');
        result.append(&mut path.as_bytes().to_vec());
        result.push(b'\x00');
        result.append(&mut hex::decode(sha).expect("SHA is not valid"));
    }

    result
}

#[test]
fn test_parse_and_serialize_tree() {
    let raw = b"100644 .gitignore\x00\x89JD\xcc\x06j\x02te\xcd&\xd64\x94\x8dV\xd1:\xf9\xaf\
                100633 LICENSE\x00\x94\xa9\xed\x02M8Yy6\x18\x15.\xa5Y\xa1h\xbb\xcb\xb5\xe2\
                80711 README.md\x00\xba\xb4\x89\xc4\xf4`\n8\xcem\xbf\xd6R\xb9\x03\x83\xa4\xaa>E";

    let tree = parse_tree(raw).unwrap();
    let serialized_raw = serialize_tree(&tree);
    assert_eq!(raw.to_vec(), serialized_raw);
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
        repository.gitdir.join("refs")
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
    let path = repository.gitdir.join(&reference);
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
    let path = repository.gitdir.join("refs").join(reference);
    let mut file = create_file(&path)?;
    let mut sha = sha.clone();
    sha.push('\n');
    file.write_all(sha.as_bytes())
        .map_err(|_| format!("Cannot write to reference file {:?}", path))?;
    Ok(())
}

//////////// utility functions //////////////

fn find_repository<P: AsRef<Path>>(path: P) -> Option<Result<GitRepository>> {
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

pub fn find_repository_required<P: AsRef<Path>>(path: P) -> Result<GitRepository> {
    find_repository(&path).ok_or(format!("Repository not found in {:?}", path.as_ref()))?
}

// fn join(parts: &[&dyn AsRef<Path>]) -> PathBuf {
//     parts.iter().fold(PathBuf::new(), |acc, p| acc.join(p.as_ref()))
// }

fn create_directory<P: AsRef<Path>>(path: P) -> Result<()> {
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

fn read_directory_content<P: AsRef<Path>>(path: P) -> Result<Vec<PathBuf>> {
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

fn check_is_empty<P: AsRef<Path>>(path: P) -> Result<()> {
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

fn read_file<P: AsRef<Path>>(file_path: P) -> Result<File> {
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

fn read_file_content<P: AsRef<Path>>(file_path: P) -> Result<Vec<u8>> {
    let mut file = read_file(&file_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .map_err(|_| format!("Cannot read file {:?}", file_path.as_ref()))?;
    Ok(data)
}

fn create_file<P: AsRef<Path>>(file_path: P) -> Result<File> {
    let file_path = file_path.as_ref();
    if let Some(parent) = file_path.parent() {
        create_directory(parent)?;
        Ok(File::create(&file_path)
           .map_err(|_| format!("Cannot create file {:?}", file_path))?)
    } else {
        Err(format!("Path not valid {:?}", file_path))
    }
}
