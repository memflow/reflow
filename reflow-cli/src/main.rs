use clap::*;
use log::Level;

use memflow::*;
use memflow_win32::*;

use reflow::*;

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
            Arg::with_name("output")
                .long("output")
                .short("o")
                .takes_value(true),
        )
        .get_matches();

    // set log level
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

    // create inventory + connector
    let inventory = unsafe { ConnectorInventory::try_new() }.unwrap();
    let connector = unsafe {
        inventory.create_connector(
            matches.value_of("connector").unwrap(),
            &ConnectorArgs::parse(matches.value_of("args").unwrap()).unwrap(),
        )
    }
    .unwrap();

    let kernel = Kernel::builder(connector)
        .build_default_caches()
        .build()
        .unwrap();

    println!("kernel: {:?}", kernel);

    let mut process = kernel.into_process("ConsoleApplication2.exe").unwrap();
    let module = process.module_info("ConsoleApplication2.exe").unwrap();

    println!("module: {:?}", module);

    // create a new oven
    let mut oven = Oven::new(process.clone());

    // ...
    oven.reflow((module.base + 0x113a7).into()).unwrap();
}
