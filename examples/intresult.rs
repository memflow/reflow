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
use reflow::prelude::v1::*;

fn main() {
    let matches = App::new("integer result example")
        .version(crate_version!())
        .author(crate_authors!())
        .arg(Arg::with_name("verbose").short("v").multiple(true))
        .arg(
            Arg::with_name("connector")
                .long("connector")
                .short("c")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("args")
                .long("args")
                .short("a")
                .takes_value(true)
                .default_value(""),
        )
        .arg(
            Arg::with_name("output")
                .long("output")
                .short("o")
                .takes_value(true),
        )
        .get_matches();

    let level = match matches.occurrences_of("verbose") {
        0 => Level::Error,
        1 => Level::Warn,
        2 => Level::Info,
        3 => Level::Debug,
        4 => Level::Trace,
        _ => Level::Trace,
    };

    simple_logger::SimpleLogger::new()
        .with_level(level.to_level_filter())
        .init()
        .unwrap();

    // build connector + os
    let inventory = Inventory::scan();
    let os = inventory
        .builder()
        .connector(matches.value_of("connector").unwrap())
        .args(Args::parse(matches.value_of("args").unwrap()).expect("unable to parse args"))
        .os("win32")
        .build()
        .expect("unable to instantiate connector / os");

    let mut process = os.into_process_by_name("ConsoleApplication1.exe").unwrap();
    let module = process.module_by_name("ConsoleApplication1.exe").unwrap();

    let mut execution = Oven::new(process)
        .stack(Stack::new().ret_addr(0x1234u64))
        .entry_point(module.base + 0x110e1);

    let result = execution.reflow().expect("unable to execute function");
    info!(
        "result: {}",
        result
            .reg_read_u64(RegisterX86::EAX)
            .expect("unable to read register") as i32
    );
}
