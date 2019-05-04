use structopt::StructOpt;
use std::path::PathBuf;

mod libwyag;

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

    #[structopt(name = "add")]
    /// Add files
    Add,
}

fn main() -> Result<(), std::io::Error> {
    let opt = Command::from_args();
    println!("{:?}", opt);
    use Command::*;
    match opt {
        Init{path} => {
            println!("Creating repository at {:?}", path);
            libwyag::create_repository(&path)?;
            println!("Done!");
            Ok(())
        },
        CatFile{fmt,hash} => {
            println!("cat-file {}", &hash);
            let current_directory = std::env::current_dir()?;
            let object = libwyag::cat_file(&current_directory, &fmt, &hash)?;
            if let Ok(object_as_string) = std::str::from_utf8(&object) {
                println!("Object: {}", object_as_string);
            } else {
                println!("Byte blob: {:?}", object);
            }
            Ok(())
        },
        HashObject{file_path, fmt, actually_write} => {
            println!("hash-object {:?}", file_path);
            let sha = libwyag::hash_object(file_path, &fmt, actually_write)?;
            println!("Calculated hash is {}", sha);
            Ok(())
        },
        Log{commit} => {
            println!("log {:?}", commit);
            if let Some(c) = commit {
                let current_directory = std::env::current_dir()?;
                println!("{}", libwyag::log(current_directory, &c)?);
            } else {
                println!("The commit hash is required at the moment...");
            }
            Ok(())
        },
        Add => {
            println!("TODO");
            Ok(())
        },
    }
}
