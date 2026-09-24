use std::env;
use std::error::Error as StdError;
use std::fmt;
use std::io::{self, Write};
use std::process::ExitCode;

use cgfs::Hierarchy;
use miette::Diagnostic;
use pam_cgroup_rs::classify::ClassifyError;
use pam_cgroup_rs::config::{Config, DEFAULT_CONFIG};
use pam_cgroup_rs::place;
use pam_cgroup_rs::user::User;

#[derive(Debug)]
enum AppError {
    Io(io::Error),
    Classify(ClassifyError),
}

type AppResult<T> = Result<T, AppError>;

impl From<io::Error> for AppError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ClassifyError> for AppError {
    fn from(error: ClassifyError) -> Self {
        Self::Classify(error)
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::Classify(error) => error.fmt(f),
        }
    }
}

impl StdError for AppError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Classify(error) => Some(error),
        }
    }
}

fn render_error(error: &dyn Diagnostic) {
    // Keep color for an interactive CLI, but let miette fall back for pipes,
    // redirected stderr, and NO_COLOR.
    let handler = miette::GraphicalReportHandler::new_themed(miette::GraphicalTheme::default())
        .without_cause_chain();
    let mut output = String::new();
    handler
        .render_report(&mut output, error)
        .expect("rendering a miette report to a String cannot fail");
    eprint!("{output}");
}

fn report_error(error: &AppError) {
    match error {
        AppError::Io(error) => eprintln!("pam-cgroup: {error}"),
        AppError::Classify(error) => render_error(error),
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: pam-cgroup <dry-run|apply|status> [--config PATH]
                    [--cgrules PATH] [--cgrules-dir PATH] [--no-cgrules-dir]
                    [--cgconfig PATH] [--user NAME] [--pid PID]"
    );
    std::process::exit(2);
}

fn cgrules_dir_path(
    cgrules: &Option<String>,
    override_dir: &Option<Option<String>>,
) -> Option<String> {
    match override_dir {
        Some(d) => d.clone(),
        None if cgrules.is_some() => Some(cgconfig::DEFAULT_CGRULES_DIR.to_string()),
        None => None,
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            report_error(&e);
            ExitCode::from(1)
        }
    }
}

fn run() -> AppResult<()> {
    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| usage());
    let mut config = None;
    let mut cgrules = None;
    let mut cgrules_dir: Option<Option<String>> = None;
    let mut cgconfig = None;
    let mut user = None;
    let mut pid = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => config = Some(args.next().unwrap_or_else(|| usage())),
            "--cgrules" => cgrules = Some(args.next().unwrap_or_else(|| usage())),
            "--cgrules-dir" => cgrules_dir = Some(Some(args.next().unwrap_or_else(|| usage()))),
            "--no-cgrules-dir" => cgrules_dir = Some(None),
            "--cgconfig" => cgconfig = Some(args.next().unwrap_or_else(|| usage())),
            "--user" => user = Some(args.next().unwrap_or_else(|| usage())),
            "--pid" => {
                let p = args.next().unwrap_or_else(|| usage());
                pid = Some(
                    p.parse::<u32>()
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
                );
            }
            "-h" | "--help" => usage(),
            _ => usage(),
        }
    }
    let config_path = config.unwrap_or_else(|| DEFAULT_CONFIG.to_string());
    match cmd.as_str() {
        "dry-run" | "apply" => {
            let user = match user {
                Some(n) => User::from_name(&n)?,
                None => User::from_uid(unsafe { libc::geteuid() as u32 })?,
            };
            let pid = pid.unwrap_or_else(std::process::id);
            let toml = match Config::load(&config_path) {
                Ok(c) => Some(c),
                Err(e) if e.kind() == io::ErrorKind::NotFound && cgrules.is_some() => None,
                Err(e) => return Err(e.into()),
            };
            let hierarchy = match toml.as_ref() {
                Some(config) => Hierarchy::open(&config.mount)?,
                None => Hierarchy::discover()?,
            };
            if cmd == "dry-run" {
                if let Some(cfg) = &toml {
                    for s in cfg.plan(&hierarchy, &user, pid)? {
                        println!(
                            "{path} uid={uid} gid={gid} mode={mode:o} file={file:o} subtree={st:?} attach={att} pid={pid}",
                            path = hierarchy
                                .mount_path()
                                .join(s.cgroup.path().as_relative())
                                .display(),
                            uid = s.uid,
                            gid = s.gid,
                            mode = s.mode,
                            file = s.file_mode,
                            st = s.subtree_control,
                            att = s.attach,
                        );
                    }
                }
                if let Some(r) = &cgrules {
                    println!(
                        "cgrules={r} dir={:?}",
                        cgrules_dir_path(&cgrules, &cgrules_dir)
                    );
                }
            } else {
                if let Some(cfg) = &toml {
                    let steps = place::apply(cfg, &hierarchy, &user, pid)?;
                    for s in steps {
                        println!(
                            "{}",
                            hierarchy
                                .mount_path()
                                .join(s.cgroup.path().as_relative())
                                .display()
                        );
                    }
                }
                if let Some(r) = &cgrules {
                    let dir = cgrules_dir_path(&cgrules, &cgrules_dir);
                    if let Some(path) = pam_cgroup_rs::classify::classify(
                        &hierarchy,
                        std::path::Path::new(r),
                        dir.as_deref().map(std::path::Path::new),
                        cgconfig.as_deref().map(std::path::Path::new),
                        &user,
                        pid,
                    )? {
                        println!("{}", path.display());
                    }
                }
            }
        }
        "status" => {
            let pid = pid.unwrap_or_else(std::process::id);
            let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
            let mut out = io::stdout();
            out.write_all(text.as_bytes())?;
        }
        _ => usage(),
    }
    Ok(())
}
