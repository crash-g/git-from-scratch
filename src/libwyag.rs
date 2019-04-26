pub mod library {
    use std::{
        fs,
        io::{prelude::*, Error, ErrorKind},
        path::{Path, PathBuf},
        result::Result::Err,

    };
    use ini::Ini;

    type Result<T> = std::result::Result<T, Error>;

    const CONFIG_INI: &str = "config";
    const GIT_PRIVATE_FOLDER: &str = ".git";

    pub struct GitRepository {
        worktree: PathBuf,
        gitdir: PathBuf,
        conf: Option<Ini>,
    }

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

    impl GitRepository {
        fn new<P: AsRef<Path>>(path: P, force: bool) -> Result<Self> {
            let worktree = path.as_ref().to_path_buf();
            let gitdir = path.as_ref().join(GIT_PRIVATE_FOLDER);

            if !force && !gitdir.is_dir() {
                return Err(Error::new(ErrorKind::InvalidInput, format!("Not a Git repository {:?}", gitdir)));
            }

            let conf = Ini::load_from_file(CONFIG_INI);
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

    fn repo_find<P: AsRef<Path>>(path: P, required: bool) -> Result<Option<GitRepository>> {
        for ancestor in path.as_ref().ancestors() {
            println!("Checking {:?}", ancestor);
            if ancestor.join(GIT_PRIVATE_FOLDER).is_dir() {
                println!("Found .git in {:?}", ancestor);
                return Ok(Some(GitRepository::new(ancestor, false)?));
            }
        }
        if required {
            Err(Error::new(ErrorKind::NotFound, format!("{:?} is not a valid Git repository", path.as_ref())))
        } else {
            Ok(None)
        }
    }

    #[test]
    fn test_repo_find() {
        let path = Path::new("/home/crash/bad/path");
        let repo = repo_find(path, false);
        assert!(repo.is_ok());
        assert!(repo.unwrap().is_none());
    }
}
