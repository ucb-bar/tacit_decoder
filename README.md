# RISC-V TACIT Decoder

## Running TACIT Decoder

```bash
cargo run -- --binary [binary] --encoded-trace [/path/to/trace] 
```

## What is TACIT?

TACIT is the **timing-accurate core instruction trace** format that is simple, efficient, and profiler-friendly.
It is also named "L-trace" under some cases, to match other risc-v trace standard naming conventions.
Comparing to other trace formats that focus on compression efficiency, it tries to capture timestamps for all control flow changes.
This includes precise timing of taken and non-taken branches, inferable and uninferable jumps.  
TACIT provides rich timing information to profilers while trying to be simple and efficient in encoding.
