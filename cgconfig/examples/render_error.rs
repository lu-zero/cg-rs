//! Render a parse error with miette's graphical handler.
//!
//! ```text
//! cargo run --example render_error -- path/to/cgconfig.conf
//! ```

use cgconfig::ConfigFile;

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "cgconfig.conf".to_owned());
    match ConfigFile::from_path(path) {
        Ok(_) => println!("ok"),
        Err(err) => {
            let handler = miette::GraphicalReportHandler::new_themed(
                miette::GraphicalTheme::unicode_nocolor(),
            );
            let mut out = String::new();
            handler.render_report(&mut out, &err).unwrap();
            println!("{out}");
        }
    }
}
