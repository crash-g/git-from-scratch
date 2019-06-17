//! An extremely simplified implementation of Git.

#![deny(rust_2018_idioms)]

use log::{info, error};
use structopt::StructOpt;
use std::path::{Path, PathBuf};

mod libwyag;
use libwyag::Result;

#[derive(Debug, StructOpt)]
#[structopt(name = "git-from-scratch", about = "An extremely simplified implementation of Git.")]
enum Command {

    #[structopt(name = "init")]
    /// Initialize the repository.
    Init {
        #[structopt(parse(from_os_str))]
        /// The path where to initialize the repository.
        path: PathBuf,
    },

    #[structopt(name = "cat-file")]
    /// Print the content of an object.
    CatFile {
        fmt: String,
        identifier: String,
    },

    #[structopt(name = "hash-object")]
    /// Compute the Git object hash from a file and optionally create the object.
    HashObject {
        #[structopt(parse(from_os_str))]
        /// The file to read.
        file_path: PathBuf,

        #[structopt(short = "t")]
        /// Specify the type of the object to create.
        fmt: String,

        #[structopt(short = "w")]
        /// Actually write the object into the repository.
        actually_write: bool,
    },

    #[structopt(name = "log")]
    /// Log commit history.
    Log {
        /// The identifier of the commit to start at.
        identifier: Option<String>,
    },

    #[structopt(name = "ls-tree")]
    /// Pretty-print a tree object.
    LsTree {
        /// The identifier of the tree object.
        identifier: String,
    },

    #[structopt(name = "checkout")]
    /// Checkout a commit or a tree inside an empty directory.
    Checkout {
        /// The identifier of a tree or of a commit.
        identifier: String,
        /// The directory where to checkout the commit or tree.
        path: PathBuf,
    },

    #[structopt(name = "show-ref")]
    /// Pretty-print all the references in the repository.
    ShowRef,

    #[structopt(name = "tag")]
    /// If no arguments are given list all tags, otherwise add a new tag.
    Tag {
        /// The name of the tag to add.
        name: Option<String>,

        /// The identifier of the object the new tag will point to.
        identifier: Option<String>,

        /// Add a tag object (otherwise, just add a tag reference).
        #[structopt(short = "a")]
        add_tag_object: bool,
    },

    #[structopt(name = "rev-parse")]
    /// Find the full hash from the given object identifier.
    RevParse {
        /// The identifier of the object.
        identifier: String,

        /// The type of the object.
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
        CatFile{fmt, identifier} => cat_file(&fmt, &identifier),
        HashObject{file_path, fmt, actually_write} =>
            hash_object(file_path, &fmt, actually_write),
        Log{identifier} => log(identifier.as_ref()),
        LsTree{identifier} => ls_tree(&identifier),
        Checkout{identifier, path} => checkout(&identifier, path),
        ShowRef => show_references(),
        Tag{name, identifier, add_tag_object} => {
            match (name, identifier) {
                (None, None) => list_tags(),
                (None, _) => Err("The tag name is required when adding a tag".to_string()),
                (_, None) => Err("The identifier of an object is required when adding a tag".to_string()),
                (Some(name), Some(identifier)) => add_tag(&name, &identifier, add_tag_object),
            }
        }
        RevParse{identifier, fmt} => rev_parse(&identifier, &fmt),
    };
    if let Err(e) = outcome {
        error!("An error occurred: {}", e);
    }
}

fn get_repository_from_current_directory() -> Result<libwyag::GitRepository> {
    let current_directory = std::env::current_dir()
        .map_err(|_| "Cannot determine current directory".to_string())?;
    libwyag::GitRepository::find_repository_required(current_directory)
}

fn init<P: AsRef<Path>>(path: P) -> Result<()> {
    libwyag::init(&path)?;
    Ok(())
}

fn cat_file(fmt: &str, identifier: &str) -> Result<()> {
    let repository = get_repository_from_current_directory()?;
    let serialized_object = libwyag::cat_file(&repository, fmt, identifier)?;

    if let Ok(object_as_string) = std::str::from_utf8(&serialized_object) {
        println!("Object: {}", object_as_string);
    } else {
        println!("Byte blob: {:?}", serialized_object);
    }
    Ok(())
}

fn hash_object<P: AsRef<Path>>(file_path: P, fmt: &str, actually_write: bool) -> Result<()> {
    let sha = libwyag::hash_object(file_path, fmt, actually_write)?;
    println!("Calculated hash is: {}", sha);
    Ok(())
}

fn log(identifier: Option<&String>) -> Result<()> {
    let repository = get_repository_from_current_directory()?;
    if let Some(id) = identifier {
        println!("{}", libwyag::log(&repository, id)?);
    } else {
        println!("{}", libwyag::log(&repository, "HEAD")?);
    }
    Ok(())
}

fn ls_tree(identifier: &str) -> Result<()> {
    let repository = get_repository_from_current_directory()?;
    let pretty_print = libwyag::ls_tree(&repository, identifier)?;
    println!("Tree: {}", pretty_print);
    Ok(())
}

fn checkout<P: AsRef<Path>>(identifier: &str, path: P) -> Result<()> {
    let repository = get_repository_from_current_directory()?;
    libwyag::checkout_tree(&repository, identifier, path)
}

fn show_references() -> Result<()> {
    let repository = get_repository_from_current_directory()?;
    println!("{}", libwyag::show_references::<&str>(&repository, None)?);
    Ok(())
}

fn list_tags() -> Result<()> {
    let repository = get_repository_from_current_directory()?;
    let path = repository.gitdir().join("refs").join("tags");
    println!("{}", libwyag::show_references(&repository, Some(path))?);
    Ok(())
}

fn add_tag(name: &str, identifier: &str, add_tag_object: bool) -> Result<()> {
    let repository = get_repository_from_current_directory()?;
    if add_tag_object {
        libwyag::create_tag_object(&repository, name, identifier)
    } else {
        libwyag::create_lightweight_tag(&repository, name, identifier)
    }
}

fn rev_parse(identifier: &str, fmt: &str) -> Result<()> {
    let repository = get_repository_from_current_directory()?;
    let sha = libwyag::recursively_resolve_identifier_by_type(&repository, identifier, fmt)?;
    println!("The complete hash associated to {} is {}", identifier, sha);
    Ok(())
}
