use structopt::StructOpt;
use std::path::PathBuf;

mod libwyag;

#[derive(Debug, StructOpt)]
#[structopt(name = "git-from-scratch", about = "The stupid content tracker.")]
enum Command {

    #[structopt(name = "add")]
    /// Add files
    Add,

    #[structopt(name = "init")]
    /// Init repository
    Init {
        #[structopt(parse(from_os_str))]
        /// The path where to init the repository
        path: PathBuf,
    }
}

fn main() -> Result<(), std::io::Error> {
    let opt = Command::from_args();
    println!("{:?}", opt);
    use Command::*;
    match opt {
        Add => {
            println!("TODO");
            Ok(())
        }
        Init{path} => {
            println!("Creating repository at {:?}", path);
            libwyag::library::repo_create(&path)?;
            println!("Done!");
            Ok(())
        }
    }
}
