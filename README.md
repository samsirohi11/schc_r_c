# SCHC-Rust 🦀

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A Rust implementation of **Static Context Header Compression (SCHC)**, featuring a streaming tree-based architecture for efficient packet compression.

## Overview

SCHC (RFC 8724) is a header compression mechanism designed for Low-Power Wide-Area Networks (LPWANs) such as LoRaWAN, Sigfox, and NB-IoT. This implementation provides:

- **Streaming Parse-Match-Compress Pipeline** - Fields are parsed on-demand during tree traversal, enabling early pruning when mismatches are detected
- **Hierarchical Rule Tree** - Rules are organized in a tree structure for efficient O(log n) matching
- **Zero-Copy Design** - Minimal memory allocations during compression
- **Modular Architecture** - Clean separation of parsing, matching, and compression logic
- **Comprehensive Test Suite** - 97+ unit and integration tests

### TODO:

- [ ] Compute CDA
- [ ] Decompression
- [ ] On the wire compression/decompression
- [ ] support for QUIC

## Features

### Supported Protocols

| Protocol | Fields                                                                                                                 |
| -------- | ---------------------------------------------------------------------------------------------------------------------- |
| **IPv4** | Version, IHL, DSCP, ECN, Length, ID, Flags, Fragment Offset, TTL, Protocol, Checksum, Source, Destination              |
| **IPv6** | Version, Traffic Class, Flow Label, Payload Length, Next Header, Hop Limit, Source/Destination (with Prefix/IID split) |
| **UDP**  | Source Port, Destination Port, Length, Checksum                                                                        |

### Matching Operators (MO)

| Operator        | Description                        |
| --------------- | ---------------------------------- |
| `equal`         | Exact value match                  |
| `ignore`        | Always matches, any value accepted |
| `match-mapping` | Value matches one from a list      |
| `MSB(n)`        | Most Significant n Bits match      |

### Compression/Decompression Actions (CDA)

| Action         | Description                                              |
| -------------- | -------------------------------------------------------- |
| `not-sent`     | Field not transmitted (reconstructed from context)       |
| `value-sent`   | Full field value transmitted                             |
| `mapping-sent` | Index into mapping table transmitted                     |
| `LSB`          | Only Least Significant Bits transmitted                  |
| `compute`      | Field computed at decompression (e.g., length, checksum) |

### Directional Field Support

Supports direction-aware field identifiers for bidirectional communication:

- `IPV6.DEV_PREFIX` / `IPV6.APP_PREFIX` - Device and Application prefixes
- `IPV6.DEV_IID` / `IPV6.APP_IID` - Interface Identifiers
- `UDP.DEV_PORT` / `UDP.APP_PORT` - Ports mapped by direction

## Installation

### From Source

```bash
git clone https://github.com/samsirohi11/schc_r_c.git
cd schc_r_c
cargo build --release
```

### As a Library

Add to your `Cargo.toml`:

```toml
[dependencies]
schc = { git = "https://github.com/samsirohi11/schc_r_c.git" }
```

## Usage

### Command Line Tools

#### Compress Packets from PCAP

```bash
cargo run --release --bin compressor -- \
    --rules test-rule.json \
    --pcap coap-observe.pcapng \
    --field-context field-context.json \
    --debug
```

**Options:**

- `-r, --rules <PATH>` - Path to rules JSON file
- `-p, --pcap <PATH>` - Path to pcapng file
- `-f, --field-context <PATH>` - Path to field context JSON
- `-d, --debug` - Enable verbose debug output
- `-m, --max-packets <N>` - Limit number of packets to process
- `--first-packet-direction <UP|DOWN>` - Direction of first packet, default: UP

#### Visualize Rule Tree

```bash
cargo run --release --bin tree_builder -- \
    --rules test-rule.json \
    --field-context field-context.json
```

### Library API

```rust
use schc::{
    RuleSet, FieldContext, build_tree, compress_packet, Direction
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load rules
    let ruleset = RuleSet::from_file("rules.json")?;
    let field_context = FieldContext::default();

    // Build compression tree
    let tree = build_tree(&ruleset.rules, &field_context);

    // Compress a packet
    let packet_data: &[u8] = &[/* raw ethernet frame */];
    let result = compress_packet(
        &tree,
        packet_data,
        Direction::Up,
        &ruleset.rules,
        &field_context,
        false, // debug mode
    )?;

    println!("Compressed {} bits -> {} bits (saved {} bits)",
        result.original_header_bits,
        result.compressed_header_bits,
        result.savings_bits());

    Ok(())
}
```

## Rule Format

Rules are defined in JSON format following the SCHC RFC 8724 specification. For this implementation, it is assumed that the rules follow the format of packet headers:

```json
[
  {
    "RuleID": 1,
    "RuleIDLength": 8,
    "Comment": "IPv6/UDP compression rule",
    "Compression": [
      { "FID": "IPV6.VER", "FL": 4, "TV": 6, "MO": "equal", "CDA": "not-sent" },
      { "FID": "IPV6.TC", "FL": 8, "MO": "ignore", "CDA": "value-sent" },
      {
        "FID": "IPV6.FL",
        "FL": 20,
        "TV": 4568,
        "MO": "MSB",
        "MO.val": 12,
        "CDA": "LSB"
      },
      { "FID": "IPV6.LEN", "MO": "ignore", "CDA": "compute" },
      {
        "FID": "IPV6.NXT",
        "FL": 8,
        "TV": 17,
        "MO": "equal",
        "CDA": "not-sent"
      },
      {
        "FID": "IPV6.HOP_LMT",
        "TV": [64, 128, 255],
        "MO": "match-mapping",
        "CDA": "mapping-sent"
      }
    ]
  }
]
```

### Field Properties

| Property | Description                                         | Required                            |
| -------- | --------------------------------------------------- | ----------------------------------- |
| `FID`    | Field Identifier (e.g., `IPV6.VER`, `UDP.SRC_PORT`) | ✓                                   |
| `FL`     | Field Length in bits                                | Optional (uses default)             |
| `TV`     | Target Value for matching                           | For `equal`, `MSB`, `match-mapping` |
| `MO`     | Matching Operator                                   | ✓                                   |
| `MO.val` | MO parameter (e.g., MSB bit count)                  | For `MSB`                           |
| `CDA`    | Compression/Decompression Action                    | ✓                                   |

## Architecture

The codebase is organized into focused modules:

```
src/
├── lib.rs              # Public API exports
├── error.rs            # Error types
├── field_id.rs         # Protocol field identifiers
├── field_context.rs    # Field definitions
├── rule.rs             # Rule parsing and structures
├── parser.rs           # Streaming packet parser
├── matcher.rs          # Value matching functions
├── compressor.rs       # Compression actions (CDAs)
├── tree.rs             # Rule tree structures
├── tree_display.rs     # Tree visualization
├── streaming_tree.rs   # Integration layer
└── bin/
    ├── compressor.rs   # CLI compression tool
    └── tree_builder.rs # Tree visualization tool
```

## Testing

Run the comprehensive test suite:

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific module tests
cargo test parser::tests
cargo test matcher::tests
cargo test compressor::tests
cargo test tree::tests

# Run integration tests
cargo test --test integration_tests
```

## Example Output

```
================================================================================
Processing packets
================================================================================

Packet 1: 48.0 bytes -> 3.5 bytes (Rule: 63/8 - Saved: 44.50 bytes / 356 bits, 92.7%)
Packet 2: 48.0 bytes -> 3.5 bytes (Rule: 63/8 - Saved: 44.50 bytes / 356 bits, 92.7%)
...

================================================================================
SUMMARY
================================================================================
Total packets processed:    100
Successfully compressed:    100
Total original header:      38400 bits (4800.0 bytes)
Total compressed header:    2800 bits (350.0 bytes)
Total bits saved:           35600 bits (4450.00 bytes, 92.7%)
Compression ratio:          13.71:1
================================================================================
```

## References

- [RFC 8724 - SCHC: Generic Framework for Static Context Header Compression and Fragmentation](https://www.rfc-editor.org/rfc/rfc8724)
- [RFC 8824 - Static Context Header Compression (SCHC) for the Constrained Application Protocol (CoAP)](https://www.rfc-editor.org/rfc/rfc8824)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
