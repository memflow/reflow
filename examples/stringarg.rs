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
 *     int result = examplefn("name4");
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
    let matches = Command::new("string argument example")
        .version(crate_version!())
        .author(crate_authors!())
        .arg(Arg::new("verbose").short('v').multiple_occurrences(true))
        .arg(
            Arg::new("connector")
                .long("connector")
                .short('c')
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::new("args")
                .long("args")
                .short('a')
                .takes_value(true)
                .default_value(""),
        )
        .arg(
            Arg::new("param")
                .long("param")
                .short('p')
                .takes_value(true)
                .required(false),
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
        .connector(matches.value_of("connector").unwrap())
        .args(str::parse(matches.value_of("args").unwrap()).expect("unable to parse args"))
        .os("win32")
        .build()
        .expect("unable to instantiate connector / os");

    let mut process = os.into_process_by_name("example_stringargs.exe").unwrap();
    let module = process.module_by_name("example_stringargs.exe").unwrap();

    let arch = process.info().proc_arch;
    let mut execution = Oven::new(arch, &mut process).expect("unable to create oven");
    execution
        .stack(Stack::new().ret_addr(0xDEADBEEFu64))?
        .entry_point(module.base + 0x112f3)?;

    if matches.is_present("param") {
        // just execute the oven with the 'param' argument
        let param = matches.value_of("param").unwrap_or_default();
        execution
            .params(Parameters::new().reg_str(RegisterX86::RCX, param))?
            .reflow()
            .expect("unable to reflow function");

        let result = execution
            .reg_read_u64(RegisterX86::EAX)
            .expect("unable to read register") as i32;
        info!("result for '{}': {}", param, result);
    } else {
        // execute the oven with all possible parameter values
        for param in vec!["name1", "name2", "name3", "name4", "name5"].into_iter() {
            execution
                .params(Parameters::new().reg_str(RegisterX86::RCX, param))?
                .reflow()
                .expect("unable to reflow function");

            let result = execution
                .reg_read_u64(RegisterX86::EAX)
                .expect("unable to read register") as i32;
            info!("result for '{}': {}", param, result);
        }
    }

    Ok(())
}
