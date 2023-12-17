/*!
 */
use clap::*;
use log::{info, Level};

use memflow::prelude::v1::*;
use reflow::prelude::v1::{Result, *};

fn main() -> Result<()> {
    let matches = Command::new("createinterface example")
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
            Arg::new("param")
                .long("param")
                .short('p')
                .action(ArgAction::Set)
                .required(false),
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

    let mut process = os
        .into_process_by_name("csgo.exe")
        .expect("csgo.exe process not found");
    let module = process
        .module_by_name("engine.dll")
        .expect("engine.dll not found");

    let create_interface = process
        .module_export_by_name(&module, "CreateInterface")
        .expect("unable to find CreateInterface export");

    let arch = process.info().proc_arch;
    let mut execution = Oven::new(arch, &mut process).expect("unable to create oven");
    execution
        .stack(Stack::new().ret_addr(0x1234u64))?
        .params(Parameters::new().push_u32(0).push_str("VEngineClient014"))?
        .entry_point(module.base + create_interface.offset)?
        .reflow()?;

    let result = execution
        .reg_read_u64(RegisterX86::EAX)
        .expect("unable to read register") as i32;
    info!("result: {:x}", result);

    Ok(())
}
