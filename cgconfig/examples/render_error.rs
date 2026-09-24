//! Render a parse error with miette's graphical handler.
//!
//! ```text
//! cargo run --example render_error -- path/to/cgconfig.conf
//! ```

use cgconfig::ConfigFile;

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: render_error <path/to/cgconfig.conf>");
        std::process::exit(2);
    };
    match ConfigFile::from_path(path) {
        Ok(_) => println!("ok"),
        Err(err) => {
            let handler =
                miette::GraphicalReportHandler::new_themed(miette::GraphicalTheme::default())
                    .without_cause_chain();
            let mut out = String::new();
            handler.render_report(&mut out, &err).unwrap();
            println!("{out}");
        }
    }
}
