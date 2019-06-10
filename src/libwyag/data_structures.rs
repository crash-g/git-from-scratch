//! Data structure and trait definitions.

use std::{
    str::from_utf8,
    io::prelude::*,
    path::{Path, PathBuf},
    result::Result::Err,
};

use linked_hash_map::LinkedHashMap;
use ini::Ini;

use super::{
    Result, Sha1,
    CONFIG_INI, GIT_PRIVATE_FOLDER,
    utils::*,
};

/// The metadata associated to a repository.
pub struct GitRepository {
    /// The path to the base directory.
    worktree: PathBuf,

    /// The path to the `.git` directory.
    gitdir: PathBuf,

    /// The path to the configuration file.
    conf: Ini,
}

/// An object in the Git model.
pub enum GitObject {
    /// `Blob`s are just arrays of bytes.
    Blob {
        data: Vec<u8>,
    },

    /// `Commit`s represent commits.
    Commit {
        data: Kvlm,
    },

    /// `Tree`s represent the content of the work tree.
    Tree {
        data: Tree,
    },

    /// `Tag`s represent tags.
    Tag {
        data: Kvlm,
    },
}

/// A key-value list with a message.
///
/// Every key is associated to one or more values.
// TODO check if it makes sense for the hashmap to become LinkedHashMap<String, Vec<String>>
pub struct Kvlm {
    data: LinkedHashMap<String, Vec<Vec<u8>>>,
}

/// A leaf in a `Tree`.
///
/// If `sha` references a `Blob`, then `path` is a path to a file,
/// if it references a `Tree`, then `path` is a path to a directory.
#[derive(Debug)]
pub struct GitTreeLeaf {
    mode: u32,
    path: String,
    sha: Sha1,
}

/// A list of `GitTreeLeaf`.
pub struct Tree {
    data: Vec<GitTreeLeaf>,
}

//////// implementations ////////

impl GitRepository {
    /// Read repository metadata from the given directory path.
    pub fn read<P: AsRef<Path>>(path: P) -> Result<Self> {
        let worktree = path.as_ref().to_path_buf();
        let gitdir = path.as_ref().join(GIT_PRIVATE_FOLDER);

        if !gitdir.is_dir() {
            return Err(format!("Not a Git repository: {:?}", gitdir));
        }

        let conf_file = gitdir.join(CONFIG_INI);
        let conf = Ini::load_from_file(&conf_file)
            .map_err(|_| format!("Configuration file is missing in {:?}", gitdir))?;

        let vers: Option<i32> = conf.section(Some("core"))
            .and_then(|properties| properties.get("repositoryformatversion"))
            .and_then(|v| v.parse().ok());

        match vers {
            Some(0) => Ok(Self{worktree, gitdir, conf: conf}),
            _ => Err(format!("Unsupported repositoryformatversion found in {:?}", conf_file))
        }
    }

    /// Create a repository at the given path.
    ///
    /// The path must be to a valid directory and to simplify things
    /// the directory must be empty.
    pub fn create<P: AsRef<Path>>(path: P) -> Result<Self> {
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

        let conf = GitRepository::default_config();
        conf.write_to_file(gitdir.join(CONFIG_INI))
            .map_err(|_| "Cannot write to config file".to_string())?;

        Ok(GitRepository{worktree: path.to_path_buf(), gitdir, conf})
    }

    /// Generate a minimal repository configuration.
    fn default_config() -> Ini {
        let mut conf = Ini::new();
        conf.with_section(Some("core".to_string()))
            .set("repositoryformatversion", "0")
            .set("filemode", "false")
            .set("bare", "false");
        conf
    }

    pub fn gitdir(&self) -> &Path {
        &self.gitdir
    }
}

impl GitObject {
    const BLOB_FMT: &'static [u8] = b"blob";
    const COMMIT_FMT: &'static [u8] = b"commit";
    const TREE_FMT: &'static [u8] = b"tree";
    const TAG_FMT: &'static [u8] = b"tag";

    pub fn new(fmt: &[u8], data: &[u8]) -> Result<GitObject> {
        if fmt == GitObject::BLOB_FMT {
            Ok(GitObject::new_blob(data.to_vec()))
        } else if fmt == GitObject::COMMIT_FMT {
            GitObject::new_commit(data)
        } else if fmt == GitObject::TREE_FMT {
            GitObject::new_tree(data)
        } else if fmt == GitObject::TAG_FMT {
            GitObject::new_tag(data)
        } else {
            Err(format!("The format {} is not supported",
                        from_utf8(fmt).expect("fmt should be UTF-8")))
        }
    }

    pub fn new_blob(data: Vec<u8>) -> GitObject {
        GitObject::Blob{data}
    }

    pub fn new_commit(data: &[u8]) -> Result<GitObject> {
        Ok(GitObject::Commit{data: Kvlm::parse_from(data)?})
    }

    pub fn new_tree(data: &[u8]) -> Result<GitObject> {
        Ok(GitObject::Tree{data: Tree::parse_from(&data)?})
    }

    pub fn new_tag(data: &[u8]) -> Result<GitObject> {
        Ok(GitObject::Tag{data: Kvlm::parse_from(data)?})
    }

    pub fn serialize(&self) -> Vec<u8> {
        use GitObject::*;
        match self {
            Blob{data} => data.to_vec(),
            Commit{data} => data.serialize(),
            Tree{data} => data.serialize(),
            Tag{data} => data.serialize(),
        }
    }

    pub fn get_fmt(&self) -> &'static [u8] {
        use GitObject::*;
        match self {
            Blob{..} => GitObject::BLOB_FMT,
            Commit{..} => GitObject::COMMIT_FMT,
            Tree{..} => GitObject::TREE_FMT,
            Tag{..} => GitObject::TAG_FMT,
        }
    }
}

impl Kvlm {
    pub fn get(&self, key: &str) -> Option<&Vec<Vec<u8>>> {
        self.data.get(key)
    }

    fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();

        for key in self.data.keys() {
            if key == "" {
                continue
            }
            for value in self.data.get(key).unwrap() {
                result.append(&mut key.as_bytes().to_vec());
                result.push(b' ');
                result.append(&mut replace(value, b"\n", b"\n "));
                result.push(b'\n');
            }
        }
        let message = self.data.get("").expect("Message not found (TODO)");
        assert_eq!(1, message.len(), "There must be exactly one message");
        let message = &message[0];
        result.push(b'\n');
        result.append(&mut message.clone());
        result
    }

    fn parse_from(raw: &[u8]) -> Result<Self> {
        let mut kvlm = Kvlm{data: LinkedHashMap::new()};
        kvlm.parse(raw)?;
        Ok(kvlm)
    }

    fn parse(&mut self, raw: &[u8]) -> Result<()> {
        let space_position = raw.iter().position(|b| *b == b' ');
        let newline_position = raw.iter().position(|b| *b == b'\n');

        match (space_position, newline_position) {
            (_, Some(np)) if np == 0 => {
                // parse message (which is right after a newline)
                self.data.insert("".to_string(), vec![raw[np + 1..].to_vec()]);
                Ok(())
            }
            (Some(sp), Some(_np)) => {
                let key = from_utf8(&raw[0..sp])
                    .map_err(|_| "Keys must be valid UTF-8".to_string())?;
                let (value, value_end) = Kvlm::parse_next_value(&raw[sp + 1..]);
                let value = replace(value, b"\n ", b"\n");
                self.insert(&key, value);

                let next_token_start = sp + value_end + 1;
                debug_assert!(next_token_start <= raw.len());
                self.parse(&raw[next_token_start..])
            }
            _ => Err("The key-value list file has an incorrect structure".to_string()),
        }
    }

    fn insert(&mut self, key: &str, value: Vec<u8>) {
        match self.data.get_mut(key) {
            None => {
                self.data.insert(key.to_string(), vec![value]);
            }
            Some(values) => {
                values.push(value);
            }
        }
    }

    fn parse_next_value(raw: &[u8]) -> (&[u8], usize) {
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

    let dict = Kvlm::parse_from(raw).unwrap();
    assert_eq!("29ff16c9c14e2652b22f8b78bb08a5a07930c147",
               from_utf8(&dict.data.get("tree").unwrap()[0]).unwrap());
    assert_eq!("206941306e8a8af65b66eaaaea388a7ae24d49a0",
               from_utf8(&dict.data.get("parent").unwrap()[0]).unwrap());
    assert_eq!("Thibault Polge <thibault@thb.lt> 1527025023 +0200",
               from_utf8(&dict.data.get("author").unwrap()[0]).unwrap());
    assert_eq!("Thibault Polge <thibault@thb.lt> 1527025044 +0200",
               from_utf8(&dict.data.get("committer").unwrap()[0]).unwrap());
    assert_eq!("another",
               from_utf8(&dict.data.get("committer").unwrap()[1]).unwrap());
    assert_eq!("-----BEGIN PGP SIGNATURE-----\n-----END PGP SIGNATURE-----",
               from_utf8(&dict.data.get("gpgsig").unwrap()[0]).unwrap());
    assert_eq!("Create first draft", from_utf8(&dict.data.get("").unwrap()[0]).unwrap());

    let raw = b"\n";
    let dict = Kvlm::parse_from(raw).unwrap();
    assert_eq!("", from_utf8(&dict.data.get("").unwrap()[0]).unwrap());

    let raw = b"";
    let dict = Kvlm::parse_from(raw);
    assert!(dict.is_err());
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

    let dict = Kvlm::parse_from(raw).unwrap();
    let serialized_raw = dict.serialize();
    assert_eq!(from_utf8(raw).unwrap(), from_utf8(&serialized_raw).unwrap());
}

impl Tree {
    pub fn get_leaves(&self) -> &Vec<GitTreeLeaf> {
        &self.data
    }

    fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();

        for GitTreeLeaf{mode, path, sha} in &self.data {
            result.append(&mut mode.to_string().as_bytes().to_vec());
            result.push(b' ');
            result.append(&mut path.as_bytes().to_vec());
            result.push(b'\x00');
            result.append(&mut hex::decode(sha).expect("SHA is not valid"));
        }

        result
    }

    fn parse_from(raw: &[u8]) -> Result<Self> {
        let mut leaves = Vec::new();
        let mut start = 0;
        while start < raw.len() {
            let (leaf, offset) = Tree::parse_leaf(&raw[start..])?;
            leaves.push(leaf);
            start += offset;
        }

        Ok(Tree{data: leaves})
    }

    fn parse_leaf(raw: &[u8]) -> Result<(GitTreeLeaf, usize)> {
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
}

impl GitTreeLeaf {
    pub fn mode(&self) -> u32 {
        self.mode
    }

    pub fn path(&self) -> &String {
        &self.path
    }

    pub fn sha(&self) -> &Sha1 {
        &self.sha
    }
}

#[test]
fn test_parse_tree() {
    let raw = b"100644 .gitignore\x00\x89JD\xcc\x06j\x02te\xcd&\xd64\x94\x8dV\xd1:\xf9\xaf\
                100633 LICENSE\x00\x94\xa9\xed\x02M8Yy6\x18\x15.\xa5Y\xa1h\xbb\xcb\xb5\xe2\
                80711 README.md\x00\xba\xb4\x89\xc4\xf4`\n8\xcem\xbf\xd6R\xb9\x03\x83\xa4\xaa>E";

    let tree = Tree::parse_from(raw).unwrap();
    assert_eq!(100644, tree.data[0].mode);
    assert_eq!(".gitignore", tree.data[0].path);
    assert_eq!("894a44cc066a027465cd26d634948d56d13af9af", tree.data[0].sha);

    assert_eq!(100633, tree.data[1].mode);
    assert_eq!("LICENSE", tree.data[1].path);
    assert_eq!("94a9ed024d3859793618152ea559a168bbcbb5e2", tree.data[1].sha);

    assert_eq!(80711, tree.data[2].mode);
    assert_eq!("README.md", tree.data[2].path);
    assert_eq!("bab489c4f4600a38ce6dbfd652b90383a4aa3e45", tree.data[2].sha);
}


#[test]
fn test_parse_and_serialize_tree() {
    let raw = b"100644 .gitignore\x00\x89JD\xcc\x06j\x02te\xcd&\xd64\x94\x8dV\xd1:\xf9\xaf\
                100633 LICENSE\x00\x94\xa9\xed\x02M8Yy6\x18\x15.\xa5Y\xa1h\xbb\xcb\xb5\xe2\
                80711 README.md\x00\xba\xb4\x89\xc4\xf4`\n8\xcem\xbf\xd6R\xb9\x03\x83\xa4\xaa>E";

    let tree = Tree::parse_from(raw).unwrap();
    let serialized_raw = tree.serialize();
    assert_eq!(raw.to_vec(), serialized_raw);
}
