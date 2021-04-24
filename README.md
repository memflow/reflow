# Reflow

Work in progress function executor for [memflow](https://github.com/memflow/memflow).

## What does it do?

Reflow uses [unicorn engine](https://github.com/unicorn-engine/unicorn) in conjunction with [memflow](https://github.com/memflow/memflow) to copy the state of a process on a target inside a unicorn vm and allows the user to execute the function safely (even with different input args).

## Example

Take the following C sample program running on a target:
```c
struct table_entry {
    const char* name;
    int value;
};

table_entry table[4];

int examplefn(const char *elem) {
    for (int i = 0; i < sizeof(table) / sizeof(table_entry); ++i) {
        if (!strcmp(table[i].name, elem)) {
            return table[i].value;
        }
    }
    return -1;
}

int main() {
    table[0] = { "name1", 1000 };
    table[1] = { "name2", 1001 };
    table[2] = { "name3", 1002 };
    table[3] = { "name4", 1003 };

    int result = examplefn("name4");
    printf("result = %d\n", result);

    system("PAUSE");
    return 0;
}
```

Lets assume the function `examplefn` is located at `module.base + 0x113a7`. The following snippet will execute the function with a different argument and outputs the result:

```rust
...

let mut process = os.into_process_by_name("example_stringargs.exe").unwrap();
let module = process.module_by_name("example_stringargs.exe").unwrap();

let mut execution = Oven::new(process)
    .stack(
        Stack::new()
            .ret_addr(0xDEADBEEFu64))
    .params(
        Parameters::new()
            .reg_str(RegisterX86::RCX, "name3"))
    .entry_point((module.base + 0x113a7).into());

let result = execution.run().expect("unable to execute function");
info!(
    "result: {}",
    result
        .reg_read_u64(RegisterX86::RAX)
        .expect("unable to read register")
);
```

More complete examples can be found in the `examples/` directory.

## Demo

[![reflow demo](http://img.youtube.com/vi/LfZfCNIHhk8/0.jpg)](http://www.youtube.com/watch?v=LfZfCNIHhk8 "reflow demo")

## License

Licensed under MIT License, see [LICENSE](LICENSE).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, shall be licensed as above, without any additional terms or conditions.
