/*!
 * Executes a function which gets a string as argument,
 *
 * # Examples:
 *
 * ```ignore
 * struct table_entry {
 *     const char* name;
 *     int value;
 * };
 *
 * table_entry table[4];
 *
 * int examplefn(const char *elem) {
 *    for (int i = 0; i < sizeof(table) / sizeof(table_entry); ++i) {
 *       if (!strcmp(table[i].name, elem)) {
 *           return table[i].value;
 *       }
 *    }
 *    return -1;
 * }
 *
 * int main() {
 *     table[0] = { "name1", 1000 };
 *     table[1] = { "name2", 1001 };
 *     table[2] = { "name3", 1002 };
 *     table[3] = { "name4", 1003 };
 *
 *     int result = testfn("name4");
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
    let matches = App::new("dump offsets example")
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
            Arg::with_name("param")
                .long("param")
                .short("p")
                .takes_value(true)
                .default_value(""),
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

    let mut process = os.into_process_by_name("example_stringargs.exe").unwrap();
    let module = process.module_by_name("example_stringargs.exe").unwrap();

    let mut execution = Oven::new(process)
        .stack(Stack::new().ret_addr(0xDEADBEEFu64))
        .params(Parameters::new().reg_str(
            RegisterX86::RCX,
            matches.value_of("param").unwrap_or_default(),
        ))
        .entry_point((module.base + 0x112f3).into());
    let result = execution.reflow().expect("unable to execute function");

    info!(
        "result: {}",
        result
            .reg_read_u64(RegisterX86::EAX)
            .expect("unable to read register") as i32
    );
}
