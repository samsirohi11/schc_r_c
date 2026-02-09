# schc

[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A Rust implementation of **Static Context Header Compression (SCHC)** per [RFC 8724](https://www.rfc-editor.org/rfc/rfc8724), featuring a streaming tree-based architecture for efficient packet compression and decompression on constrained links.

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
schc = { git = "https://github.com/samsirohi11/schc_r_c.git" }
```

Compress an IPv6/UDP packet:

```rust
use schc::{RuleSet, Direction, compress_packet, build_tree};

// Load rules from JSON
let rules: RuleSet = serde_json::from_str(rules_json)?;

// Build the matching tree once
let tree = build_tree(&rules);

// Compress a packet (assumes Ethernet framing)
let result = compress_packet(&rules, &tree, raw_packet, Direction::Up)?;
println!("Rule {}/{}: {} -> {} bits",
    result.rule_id, result.rule_id_length,
    raw_packet.len() * 8, result.total_bits());

// Decompress back
let decompressed = schc::decompress_packet(&rules, &result.to_bytes())?;
let headers = schc::build_headers(&decompressed)?;
```

## Overview

SCHC is a header compression mechanism designed for Low-Power Wide-Area Networks (LPWANs) and constrained links. This implementation provides:

- **Streaming Parse-Match-Compress Pipeline** -- fields are parsed on-demand during tree traversal, enabling early pruning when mismatches are detected
- **SID-Driven Protocol Detection** -- protocol layers (UDP, QUIC, CoAP, ICMPv6) are determined by the `FieldId` requested, not by inspecting next-header values or well-known ports
- **Hierarchical Rule Tree** -- rules are organized in a tree structure for efficient O(log n) matching
- **Bidirectional Support** -- direction-aware fields (`DEV_*`/`APP_*`) resolve to source/destination based on packet direction
- **Header Reconstruction** -- decompression rebuilds complete protocol headers with computed checksums and lengths

## Supported Protocols

| Protocol   | Fields                                                                                                                 |
| ---------- | ---------------------------------------------------------------------------------------------------------------------- |
| **IPv4**   | Version, IHL, DSCP, ECN, Length, ID, Flags, Fragment Offset, TTL, Protocol, Checksum, Source, Destination              |
| **IPv6**   | Version, Traffic Class, Flow Label, Payload Length, Next Header, Hop Limit, Source/Destination (with Prefix/IID split) |
| **UDP**    | Source Port, Destination Port, Length, Checksum                                                                        |
| **CoAP**   | Version, Type, TKL, Code, Message ID, Token, Options (Uri-Path, Content-Format, etc.), Payload Marker                 |
| **ICMPv6** | Type, Code, Checksum, Identifier, Sequence, MTU, Pointer, Payload                                                     |
| **QUIC**   | First Byte, Version, DCID Length, DCID, SCID Length, SCID                                                              |

## Matching Operators (MO)

| Operator        | Description                        |
| --------------- | ---------------------------------- |
| `equal`         | Exact value match                  |
| `ignore`        | Always matches, any value accepted |
| `match-mapping` | Value matches one from a list      |
| `MSB(n)`        | Most Significant n Bits match      |

## Compression/Decompression Actions (CDA)

| Action         | Description                                              |
| -------------- | -------------------------------------------------------- |
| `not-sent`     | Field not transmitted (reconstructed from context)       |
| `value-sent`   | Full field value transmitted                             |
| `mapping-sent` | Index into mapping table transmitted                     |
| `LSB`          | Only Least Significant Bits transmitted                  |
| `compute`      | Field computed at decompression (e.g., length, checksum) |

## MO/CDA Validation

Rules are validated per RFC 8724 Section 7.3 at load time:

| MO              | Valid CDA(s)            | Requirements      |
| --------------- | ----------------------- | ----------------- |
| `equal`         | `not-sent`              | TV required       |
| `ignore`        | `value-sent`, `compute` | -                 |
| `MSB`           | `LSB`                   | TV required       |
| `match-mapping` | `mapping-sent`          | Array TV required |

Invalid combinations are rejected with descriptive error messages.

## Directional Field Support

Direction-aware field identifiers for bidirectional communication:

- `IPV6.DEV_PREFIX` / `IPV6.APP_PREFIX` -- Device and Application prefixes
- `IPV6.DEV_IID` / `IPV6.APP_IID` -- Interface Identifiers
- `UDP.DEV_PORT` / `UDP.APP_PORT` -- Ports mapped by direction

Per RFC 8724, individual fields can specify a Direction Indicator (`"up"`, `"down"`, `"bi"`) to control when rules apply.

## Link Layer Configuration

The parser supports configurable link layer handling:

| Link Layer  | Description                                |
| ----------- | ------------------------------------------ |
| `None`      | Raw IP packets (no link layer header)      |
| `Ethernet`  | Standard 14-byte Ethernet header (default) |
| `Custom(n)` | Custom link layer with n-byte header       |

Use `compress_packet_with_link_layer()` for non-Ethernet packets.

## SID-Driven Protocol Detection

Each `FieldId` variant maps 1:1 to a SID from YANG/CORECONF. The `FieldId::protocol()` method returns the protocol family a field belongs to (`Ipv4`, `Ipv6`, `Udp`, `Coap`, `Quic`, `Icmpv6`).

When the rule tree requests a field, the parser computes the byte offset based on the protocol stack structure and attempts extraction -- no next-header or port checks needed. The rule tree's matching operators handle correctness: if a rule requests `UdpSrcPort` on an ICMPv6 packet, the `Ipv6Nxt` field with `MO=Equal, TV=17` prunes that branch before deeper fields are evaluated.

This enables compression of protocols on non-standard ports (e.g., CoAP on port 9999, QUIC on port 1234) without any configuration changes.

## Rule Format

Rules are defined in JSON following RFC 8724:

```json
[
  {
    "RuleID": 1,
    "RuleIDLength": 8,
    "Compression": [
      { "FID": "IPV6.VER", "FL": 4, "TV": 6, "MO": "equal", "CDA": "not-sent" },
      { "FID": "IPV6.TC", "FL": 8, "MO": "ignore", "CDA": "value-sent" },
      { "FID": "IPV6.FL", "FL": 20, "TV": 4568, "MO": "MSB", "MO.val": 12, "CDA": "LSB" },
      { "FID": "IPV6.LEN", "MO": "ignore", "CDA": "compute" },
      { "FID": "IPV6.NXT", "FL": 8, "TV": 17, "MO": "equal", "CDA": "not-sent" },
      { "FID": "IPV6.HOP_LMT", "TV": [64, 128, 255], "MO": "match-mapping", "CDA": "mapping-sent" }
    ]
  }
]
```

| Property | Description                                         | Required                            |
| -------- | --------------------------------------------------- | ----------------------------------- |
| `FID`    | Field Identifier (e.g., `IPV6.VER`, `UDP.SRC_PORT`) | Yes                                 |
| `FL`     | Field Length in bits                                 | Optional (uses protocol default)    |
| `DI`     | Direction Indicator (`"up"`, `"down"`, `"bi"`)      | Optional (default: `"bi"`)          |
| `TV`     | Target Value for matching                           | For `equal`, `MSB`, `match-mapping` |
| `MO`     | Matching Operator                                   | Yes                                 |
| `MO.val` | MO parameter (e.g., MSB bit count)                  | For `MSB`                           |
| `CDA`    | Compression/Decompression Action                    | Yes                                 |

## Architecture

```
src/
  lib.rs              # Public API re-exports
  error.rs            # Error types (SchcError)
  field_id.rs         # Protocol field identifiers (generated from field-context.json)
  rule.rs             # Rule parsing and structures
  parser.rs           # Streaming packet parser (SID-driven, permissive)
  matcher.rs          # Matching operators (equal, ignore, MSB, match-mapping)
  compressor.rs       # Compression actions (CDAs)
  decompressor.rs     # Decompression (rule ID matching, field restoration)
  packet_builder.rs   # Header reconstruction with checksums
  tree.rs             # Rule tree structures
  tree_display.rs     # Tree visualization
  streaming_tree.rs   # Integration layer (unified parse+match+compress)
  bit_buffer.rs       # Bit-level I/O
  build.rs            # Code generation for FieldId enum from field-context.json
bin/
  compressor.rs       # CLI: compress packets from pcap files
  live_compressor.rs  # CLI: live interface capture and compress
  tree_builder.rs     # CLI: rule tree visualization
```

## CLI Tools

Build with `cargo build --release --features bins`.

```bash
# Compress packets from a pcap file
cargo run --release --features bins --bin compressor -- \
    --rules rules.json --pcap capture.pcapng --verify

# Visualize the rule tree
cargo run --release --features bins --bin tree_builder -- \
    --rules rules.json

# Live capture and compress (requires elevated privileges)
cargo run --release --features bins --bin live_compressor -- \
    --interface eth0 --rules rules.json
```

## Minimum Supported Rust Version

The MSRV is **1.85** (Rust edition 2024).

## References

- [RFC 8724 - SCHC: Generic Framework for Static Context Header Compression and Fragmentation](https://www.rfc-editor.org/rfc/rfc8724)
- [RFC 8824 - Static Context Header Compression (SCHC) for CoAP](https://www.rfc-editor.org/rfc/rfc8824)
- [RFC 9363 - YANG Data Model for SCHC](https://datatracker.ietf.org/doc/rfc9363/)
- [RFC 9011 - SCHC over LoRaWAN](https://www.rfc-editor.org/rfc/rfc9011)

## License

MIT
