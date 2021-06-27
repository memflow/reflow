/*!
 */
use clap::*;
use log::{info, Level};

use memflow::prelude::v1::*;
use reflow::prelude::v1::{Result, *};

fn main() -> Result<()> {
    let matches = App::new("createinterface example")
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

    let mut process = os
        .into_process_by_name("csgo.exe")
        .expect("csgo.exe process not found");
    let module = process
        .module_by_name("engine.dll")
        .expect("engine.dll not found");

    let create_interface = process
        .module_export_by_name(&module, "CreateInterface")
        .expect("unable to find CreateInterface export");

    let mut execution = new_oven(&mut process)?;

    let result = execution
        .stack(Stack::new().ret_addr(0x1234u64))?
        .params(Parameters::new().push_u32(0).push_str("VEngineClient014"))?
        .entry_point(module.base + create_interface.offset)?
        .reflow()?;

    info!(
        "result: {:x}",
        result
            .reg_read_u64(RegisterX86::EAX)
            .expect("unable to read register") as i32
    );

    Ok(())
}
