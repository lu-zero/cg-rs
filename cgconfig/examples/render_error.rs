//! Render a parse error with miette's graphical handler.
//!
//! ```text
//! cargo run --example render_error
//! ```

use cgconfig::parse_cgconfig_in;

fn main() {
    let text = "# student layout\n\
                group students {\n\
                \tcpu {}\n\
                }\n\
                template students/%u {\n\
                \tperm {\n\
                \t\ttask { uid = %u; gid = students }\n\
                \t}\n\
                }\n";
    match parse_cgconfig_in("cgconfig.conf", text) {
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
