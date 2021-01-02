use std::cell::RefCell;
use std::sync::Arc;

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
    let inventory = unsafe { ConnectorInventory::scan() };
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

    let mut process = kernel.into_process("ConsoleApplication1.exe").unwrap();
    let module = process.module_info("ConsoleApplication1.exe").unwrap();

    println!("module: {:?}", module);

    /*
    let execution = Oven::new()
      .stack(Stack::new() // < We do not have the unicorn context here to create the stack on the get-go
        .ret_addr(0xDEADBEEFu64)
        .push_str("test string on stack")
        .push_obj(some_pod_object))
      .entry_point(func_addr);
        */

    // create a new oven
    let cloned_proc = Arc::new(RefCell::new(process.clone()));
    let stack = Stack::new()
        .base(size::gb(1000) as u64)
        .size(size::mb(31) as u64)
        .ret_addr(0x1234u64)
        .push64(0);
    let mut oven = Oven::new(cloned_proc, stack);

    // ...
    oven.reflow((module.base + 0x110e1).into()).unwrap();
    //oven.reflow((module.base + 0x110e1).into()).unwrap();
    //oven.reflow((module.base + 0x110e1).into()).unwrap();
}
