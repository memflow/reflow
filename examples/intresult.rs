/*!
 * Executes a function which returns an integer.
 *
 * # Examples:
 *
 * ```ignore
 * int examplefn() {
 *     int a = 10;
 *     int b = 20;
 *     int c = 30;
 *     int d = a + b;
 *     int e = c - d;
 *     return e + d;
 * }
 *
 * int main() {
 *     int result = examplefn();
 *     printf("result = %d\n", result);
 *
 *     system("PAUSE");
 *     return 0;
 * }
 * ```
 */
use clap::*;
use log::{info, Level};

use memflow::prelude::v1::*;
use reflow::prelude::v1::{Result, *};

fn main() -> Result<()> {
    let matches = Command::new("integer result example")
        .version(crate_version!())
        .author(crate_authors!())
        .arg(Arg::new("verbose").short('v').action(ArgAction::Count))
        .arg(
            Arg::new("connector")
                .long("connector")
                .short('c')
                .action(ArgAction::Set)
                .required(true),
        )
        .arg(
            Arg::new("args")
                .long("args")
                .short('a')
                .action(ArgAction::Set)
                .default_value(""),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .short('o')
                .action(ArgAction::Set),
        )
        .get_matches();

    let level = match matches.get_count("verbose") {
        0 => Level::Error,
        1 => Level::Warn,
        2 => Level::Info,
        3 => Level::Debug,
        4 => Level::Trace,
        _ => Level::Trace,
    };
    simplelog::TermLogger::init(
        level.to_level_filter(),
        simplelog::Config::default(),
        simplelog::TerminalMode::Stdout,
        simplelog::ColorChoice::Auto,
    )
    .unwrap();

    // build connector + os
    let inventory = Inventory::scan();
    let os = inventory
        .builder()
        .connector(matches.get_one::<String>("connector").unwrap())
        .args(
            matches
                .get_one::<String>("args")
                .unwrap()
                .parse()
                .expect("unable to parse args"),
        )
        .os("win32")
        .build()
        .expect("unable to instantiate connector / os");

    let mut process = os.into_process_by_name("ConsoleApplication1.exe").unwrap();
    let module = process.module_by_name("ConsoleApplication1.exe").unwrap();

    let arch = process.info().proc_arch;
    let mut execution = Oven::new(arch, &mut process).expect("unable to create oven");
    execution
        .stack(Stack::new().ret_addr(0x1234u64))?
        .entry_point(module.base + 0x110e1)?
        .reflow()?;

    let result = execution
        .reg_read_u64(RegisterX86::EAX)
        .expect("unable to read register") as i32;
    info!("result: {}", result);

    Ok(())
}
