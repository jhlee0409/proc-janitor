use std::fs;

include!("src/cli.rs");

fn main() {
    let out_dir = std::path::PathBuf::from(
        std::env::var("OUT_DIR").unwrap_or_else(|_| "target/man".to_string()),
    );

    let cmd = <Cli as clap::CommandFactory>::command();
    let man = clap_mangen::Man::new(cmd);
    let mut buffer: Vec<u8> = Vec::new();
    man.render(&mut buffer)
        .expect("Failed to generate man page");

    let man_dir = out_dir.join("man");
    fs::create_dir_all(&man_dir).expect("Failed to create man directory");
    fs::write(man_dir.join("proc-janitor.1"), buffer).expect("Failed to write man page");
}
