#![deny(rust_2018_idioms)]

use log::{info, debug, error};
use structopt::StructOpt;
use std::path::PathBuf;

mod libwyag;
use libwyag::Result;

#[derive(Debug, StructOpt)]
#[structopt(name = "git-from-scratch", about = "The stupid content tracker.")]
enum Command {

    #[structopt(name = "init")]
    /// Init repository
    Init {
        #[structopt(parse(from_os_str))]
        /// The path where to init the repository
        path: PathBuf,
    },

    #[structopt(name = "cat-file")]
    /// Print the content of an object
    CatFile {
        fmt: String,
        hash: libwyag::Sha1,
    },

    #[structopt(name = "hash-object")]
    /// Compute object ID and optionally create a blob from a file
    HashObject {
        #[structopt(parse(from_os_str))]
        /// The file to read
        file_path: PathBuf,

        #[structopt(short = "t")]
        /// Specify the type
        fmt: String,

        #[structopt(short = "w")]
        /// Actually write the object into the database
        actually_write: bool,
    },

    #[structopt(name = "log")]
    /// Log history
    Log {
        /// The hash of the commit to start at
        commit: Option<libwyag::Sha1>,
    },

    #[structopt(name = "ls-tree")]
    /// Pretty-print a tree object
    LsTree {
        /// The hash of the tree object
        hash: libwyag::Sha1,
    },

    #[structopt(name = "checkout")]
    /// Checkout a commit inside an empty directory
    Checkout {
        /// The hash of a tree or of a commit
        hash: libwyag::Sha1,
        /// The directory where to checkout the commit
        path: PathBuf,
    },

    #[structopt(name = "show-ref")]
    /// Print all the references in the repository
    ShowRef,

    #[structopt(name = "tag")]
    /// List all tags or add a new tag
    Tag {
        /// The name of the tag
        name: Option<String>,

        /// The object the new tag will point to
        object: Option<libwyag::Sha1>,

        /// Add a tag object (otherwise, just add a tag reference)
        #[structopt(short = "a")]
        add_tag_object: bool,
    },

    #[structopt(name = "rev-parse")]
    /// Parse revision (or other objects) identifiers
    RevParse {
        /// The identifier of the object
        name: String,

        /// The type of the object
        fmt: String,
    },
}

fn main() {
    simple_logger::init_with_level(log::Level::Debug).unwrap();

    let opt = Command::from_args();
    info!("{:?}", opt);

    use Command::*;
    let outcome = match opt {
        Init{path} => init(path),
        CatFile{fmt, hash} => cat_file(fmt, hash),
        HashObject{file_path, fmt, actually_write} =>
            hash_object(file_path, fmt, actually_write),
        Log{commit} => log(commit),
        LsTree{hash} => ls_tree(hash),
        Checkout{hash, path} => checkout(hash, path),
        ShowRef => show_references(),
        Tag{name, object, add_tag_object} => {
            match (name, object) {
                (None, None) => list_tags(),
                (None, _) => Err("The tag name is required when adding a tag".to_string()),
                (Some(name), object) => add_tag(name, object, add_tag_object),
            }
        }
        RevParse{name, fmt} => rev_parse(name, fmt),
    };
    if let Err(e) = outcome {
        error!("An error occurred: {}", e);
    }
}

fn init(path: PathBuf) -> Result<()> {
    debug!("Creating repository at {:?}", path);
    libwyag::init(&path)?;
    Ok(())
}

fn cat_file(fmt: String, sha: libwyag::Sha1) -> Result<()> {
    debug!("cat-file {}", &sha);

    let current_directory = std::env::current_dir()
        .map_err(|_| "Cannot determine current directory".to_string())?;
    let repository = libwyag::GitRepository::find_repository_required(current_directory)?;
    let object = libwyag::cat_file(&repository, &fmt, &sha)?;

    if let Ok(object_as_string) = std::str::from_utf8(&object) {
        println!("Object: {}", object_as_string);
    } else {
        println!("Byte blob: {:?}", object);
    }
    Ok(())
}

fn hash_object(file_path: PathBuf, fmt: String, actually_write: bool) -> Result<()> {
    debug!("hash-object {:?}", file_path);
    let sha = libwyag::hash_object(file_path, &fmt, actually_write)?;
    println!("Calculated hash is {}", sha);
    Ok(())
}

fn log(commit: Option<libwyag::Sha1>) -> Result<()> {
    debug!("log {:?}", commit);
    if let Some(c) = commit {
        let current_directory = std::env::current_dir()
            .map_err(|_| "Cannot determine current directory".to_string())?;
        println!("{}", libwyag::log(current_directory, &c)?);
    } else {
        println!("The commit hash is required at the moment..."); // TODO
    }
    Ok(())
}

fn ls_tree(hash: libwyag::Sha1) -> Result<()> {
    debug!("ls-tree {}", &hash);
    let current_directory = std::env::current_dir()
        .map_err(|_| "Cannot determine current directory".to_string())?;
    let repository = libwyag::GitRepository::find_repository_required(current_directory)?;
    let pretty_print = libwyag::ls_tree(&repository, &hash)?;
    println!("Tree: {}", pretty_print);
    Ok(())
}

fn checkout(hash: libwyag::Sha1, path: PathBuf) -> Result<()> {
    debug!("checkout {} to {:?}", &hash, path);
    let current_directory = std::env::current_dir()
        .map_err(|_| "Cannot determine current directory".to_string())?;
    let repository = libwyag::GitRepository::find_repository_required(current_directory)?;
    libwyag::checkout_tree(&repository, &hash, path)
}

fn show_references() -> Result<()> {
    debug!("show-ref");
    let current_directory = std::env::current_dir()
        .map_err(|_| "Cannot determine current directory".to_string())?;
    let repository = libwyag::GitRepository::find_repository_required(current_directory)?;
    libwyag::show_references::<PathBuf>(&repository, None)?;
    Ok(())
}

fn list_tags() -> Result<()> {
    debug!("tag");
    let current_directory = std::env::current_dir()
        .map_err(|_| "Cannot determine current directory".to_string())?;
    let repository = libwyag::GitRepository::find_repository_required(current_directory)?;
    libwyag::show_references(&repository, Some(repository.gitdir().join("refs").join("tags")))?;
    Ok(())
}

fn add_tag(name: String, object: Option<libwyag::Sha1>, add_tag_object: bool) -> Result<()> {
    debug!("tag with name {} pointing to {:?}", name, object);
    let current_directory = std::env::current_dir()
        .map_err(|_| "Cannot determine current directory".to_string())?;
    let repository = libwyag::GitRepository::find_repository_required(current_directory)?;

    if add_tag_object {
        libwyag::create_tag_object(&repository, &name, &object.expect("An object is required at the moment (TODO)"))
    } else {
        libwyag::create_tag(&repository, &name, &object.expect("An object is required at the moment (TODO)"))
    }
}

fn rev_parse(name: String, fmt: String) -> Result<()> {
    debug!("rev-parse");
    let current_directory = std::env::current_dir()
        .map_err(|_| "Cannot determine current directory".to_string())?;
    let repository = libwyag::GitRepository::find_repository_required(current_directory)?;
    let sha = libwyag::recursively_resolve_object_by_type(&repository, &name, &fmt)?;
    println!("The complete hash associated to {} is {}", name, sha);
    Ok(())
}
