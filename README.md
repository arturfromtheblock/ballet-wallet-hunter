<h1 align="center">Ballet Wallet Hunter</h1>
<br>
<p align="center">
  <span>A Go-based BIP38 passphrase search tool built for educational analysis of the Ballet Wallet CTF challenge published by Bobby Lee on July 31, 2020.</span>
  ![macOS](https://img.shields.io/badge/macOS-000000?style=flat&logo=apple&logoColor=white) ![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=flat&logo=ubuntu&logoColor=white)
</p>

<img src="https://raw.githubusercontent.com/arturfromtheblock/ballet-wallet-hunter/refs/heads/master/img/balletwallethunter.png">

---

## What is This?

On **July 31, 2020**, Ballet Wallet founder Bobby Lee published a public Capture The Flag (CTF) challenge to demonstrate the security properties of Ballet’s BIP38-based wallet design.

### The Challenge Setup

The challenge consisted of **two wallets**:

- **Wallet #1**: Contains **1 BTC**. A BIP38 encrypted private key (EPK) and confirmation code are provided. The passphrase is unknown and must be recovered.
  - **Target Address:** `1JxWyNrkgYvgsHu8hVQZqTXEB9RftRGP5m`
  - **EPK:** `6PnQmAyBky9ZXJyZBv9QSGRUXkKh9HfnVsZWPn4YtcwoKy5vufUgfA3Ld7`
  - **Confirmation Code:** `cfrm38VUGuohnUuosBHHzLjQoZ2oPTyt1tGPLsfQcKq2gXT8fkC6XJAyc4sJkXrrpy22zMVbnP5`

- **Wallet #2**: Contains **1 BTC**. The passphrase and confirmation code are known, but the encrypted private key is not provided. This demonstrates that a passphrase and confirmation code alone are not sufficient to reconstruct the private key or spend funds.
  - **Target Address:** `1QGtbKxx6FKDD66LwnrzHCAHmyZ7mDHqC4`
  - **Passphrase:** `594Y-L2RW-4ME7-2XVX-9B41`
  - **Confirmation Code:** `cfrm38VUh2i5qzzCqedWtc8ekFxT3UpcQnfb42JRrLbTWCRTfgVTCXqLp3FYxqiyQDo4D3DyWzY`

### The Passphrase Pattern

Ballet Wallet passphrases follow a fixed-format pattern:

```text
XXXX-XXXX-XXXX-XXXX-XXXX
```

Each `X` is an uppercase alphanumeric character from `A-Z` or `0-9`, giving **36 possibilities per position**.

**This tool attempts to search the passphrase for Wallet #1** using pattern masking, precomputed values, and parallel execution to reduce avoidable overhead. The full 20-character space remains cryptographically infeasible without additional hints or partial knowledge.

### Why This Matters

The challenge illustrates an important security property of BIP38 in the EC-multiply workflow used by Ballet: access to funds requires both the encrypted private key material and the correct passphrase. A confirmation code can help verify that a passphrase matches the intended wallet setup, but it does not reveal the private key.

## Features

- **Pattern Masking System**: Fix known characters and search only unknown positions
  - Example: `A1XX-XXXX-B2XX-XXXX-C3XX` → only 14 unknown positions remain
- **Parallel Workers**: Uses goroutines across available CPU cores
- **Precomputed Data**: Avoids repeating static BIP38 parsing work
- **Confirmation-Code-Aware Verification**: Uses challenge-specific data to reduce unnecessary work where possible
- **Live Status Output**: Shows current rate and last-tested candidate
- **Cross-platform**: Native builds for Intel and Apple Silicon Macs

## Search Space Reality Check

| Pattern                    | Unknown Positions | Search Space       | Time @ 40/s   |
| :------------------------- | :---------------- | :----------------- | :------------ |
| `XXXX-XXXX-XXXX-XXXX-XXXX` | 20                | 36²⁰ ≈ 1.34×10³¹   | ~10²² years   |
| `A1XX-XXXX-B2XX-XXXX-C3XX` | 14                | 36¹⁴ ≈ 6.14×10²¹   | ~10¹³ years   |
| `2026-XXXX-XXXX-XXXX-XXXX` | 16                | 36¹⁶ ≈ 7.96×10²⁴   | ~10¹⁶ years   |

**This project is intended for educational analysis and authorized testing only. Without additional constraints, the full search space is not practically brute-forceable.**

## Installation

### Prerequisites

- macOS (Intel or Apple Silicon)
- Go

```bash
# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Go
brew install go
```

### Build from Source

```bash
# Clone the repository
git clone https://github.com/arturfromtheblock/ballet-wallet-hunter.git
cd ballet-wallet-hunter

# Build for the host architecture
make native

# Or manually:

# Apple Silicon
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o bwh-silicon -ldflags="-s -w" main.go

# Intel Mac
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o bwh-intel -ldflags="-s -w" main.go

# Generic local build
go build -o bwh -ldflags="-s -w" main.go
```

## Configuration

Create a `config.txt` file in the project directory:

```text
# BIP38 encrypted private key (Base58Check, usually starts with 6P)
EPK=6PnQmAyBky9ZXJyZBv9QSGRUXkKh9HfnVsZWPn4YtcwoKy5vufUgfA3Ld7

# Target Bitcoin address (optional, for logging)
TARGET_ADDRESS=1JxWyNrkgYvgsHu8hVQZqTXEB9RftRGP5m

# BIP38 confirmation code (optional, for challenge-specific verification)
CONFIRMATION_CODE=cfrm38VUGuohnUuosBHHzLjQoZ2oPTyt1tGPLsfQcKq2gXT8fkC6XJAyc4sJkXrrpy22zMVbnP5

# Search mode: "random" or "sequential"
MODE=random

# Number of workers (0 = auto-detect CPU cores)
WORKERS=0

# Passphrase pattern: X = unknown alphanumeric position, anything else = fixed
PATTERN=XXXX-XXXX-XXXX-XXXX-XXXX
```

### Environment Variables

You can also configure the tool with environment variables:

```bash
export BIP38_EPK="6PnQmAyBky9ZXJyZBv9QSGRUXkKh9HfnVsZWPn4YtcwoKy5vufUgfA3Ld7"
export BIP38_TARGET="1JxWyNrkgYvgsHu8hVQZqTXEB9RftRGP5m"
export BIP38_PATTERN="A1XX-XXXX-B2XX-XXXX-C3XX"
export BIP38_WORKERS=8
./bwh-silicon
```

## Usage

```bash
# Run with config.txt
./bwh-silicon

# Example output:
# ⚡ [760.8s] 28773 tested | 37.8/s | Last: JQKY-TRMH-77L1-13XC-CGLK
```

### Pattern Syntax

| Character      | Meaning                     |
| -------------- | --------------------------- |
| `X` or `x`     | Unknown alphanumeric (`A-Z`, `0-9`) |
| `?`            | Unknown numeric only (`0-9`) |
| `A-Z`, `0-9`   | Fixed character             |
| `-`            | Fixed separator             |

**Examples:**

- `XXXX-XXXX-XXXX-XXXX-XXXX` — Full search space (36²⁰ combinations)
- `2026-XXXX-XXXX-XXXX-XXXX` — Prefix fixed, rest unknown (36¹⁶ combinations)
- `TEST-XXXX-XXXX-XXXX-XXXX` — Word fixed, rest unknown (36¹⁶ combinations)
- `A1XX-XXXX-B2XX-XXXX-C3XX` — Multiple fixed positions (36¹⁴ combinations)
- `X?XX-????-XXXX-?X?X-XXX?` — Mixed pattern with numeric-only positions (36¹² × 10⁸ ≈ 4.74×10²⁶ combinations)

## Performance Tips

1. **Use Pattern Masking**: Every fixed alphanumeric position reduces the search space by a factor of 36.
2. **Use a Native Binary**: On Apple Silicon, prefer the ARM64 build instead of Rosetta.
3. **Avoid Background Load**: BIP38 verification is CPU- and memory-intensive.
4. **Benchmark on Your Own Hardware**: Actual throughput depends heavily on implementation details, CPU architecture, memory bandwidth, and whether confirmation-code checks can short-circuit parts of the pipeline.

## Technical Details

### Why BIP38 is Hard to Search

BIP38 uses **scrypt** as a key-derivation function specifically to make passphrase guessing expensive. Scrypt is deliberately computationally heavy and memory-intensive, which makes brute-force attacks far slower than attacks against simple hash-based formats.

### BIP38 Modes

BIP38 supports more than one workflow:

- **Non-EC-multiply mode**: Direct encryption of a private key with a passphrase
- **EC-multiply mode**: A two-party workflow where one side can generate encrypted key material from a passpoint without learning the final passphrase-derived private key

The Ballet challenge uses the **EC-multiply** workflow, which is why confirmation codes and passpoint-based derivation are relevant here.

### Scrypt Parameters Used by BIP38

In the EC-multiply workflow, the relevant derivation steps are:

**Scrypt #1:**

```text
scrypt(passphrase, ownerSalt, N=16384, r=8, p=8, dkLen=32)
```

**Scrypt #2:**

```text
scrypt(passpoint, addressHash + ownerEntropy, N=1024, r=1, p=1, dkLen=64)
```

These parameters are defined by the BIP38 specification for the relevant workflows.

### What the Parameters Mean

| Parameter | Value | Meaning |
| --------- | ----- | ------- |
| **N**     | 16384 | CPU/memory cost factor; must be a power of 2 |
| **r**     | 8     | Block size parameter affecting memory usage |
| **p**     | 8     | Parallelization parameter |
| **dkLen** | 32    | Output length in bytes for the first derivation |

### Memory and Computation Cost

For the expensive scrypt step, the dominant working memory is on the order of:

```text
Memory ≈ 128 × N × r bytes
       ≈ 128 × 16384 × 8
       ≈ 16 MiB
```

Actual total memory usage may be higher depending on implementation details, buffering, concurrency, and how many workers run at once.

This makes each passphrase attempt expensive compared with ordinary password hashing:

- Significant memory pressure per worker
- Heavy CPU usage
- Poor scaling compared with simpler hash functions
- Strong resistance to massive acceleration relative to SHA-256-style workloads

### Why GPUs Help Less Than With Simple Hashes

Scrypt was designed to reduce the advantage of hardware that excels at massively parallel, low-memory hashing. GPUs can still accelerate scrypt workloads, but the speedup is much smaller than the extreme gains often seen with simpler algorithms such as SHA-256.

### The EC-Multiply Verification Pipeline

For a challenge like this, a candidate passphrase typically flows through these stages:

1. Decode the encrypted key and extract static metadata
2. Run **scrypt #1** with the candidate passphrase and owner salt
3. Derive the passfactor and passpoint
4. Use **scrypt #2** with the passpoint and address-derived data
5. Decrypt the encrypted seed material
6. Derive the final factor and private key material
7. Reconstruct the address and compare it against the embedded hash and expected target

The main bottlenecks are the first scrypt derivation, elliptic-curve operations, and the second derivation/decryption path.

### Performance Reality

Practical throughput varies substantially by hardware and implementation. For that reason, this repository reports live measured rates during execution instead of claiming universal benchmark numbers.

Even so, the full 20-character Ballet passphrase format remains astronomically large:

- 36²⁰ ≈ 1.34×10³¹ total combinations
- At 40 checks per second, exhaustive search would take roughly 10²² years
- Even very large parallel hardware deployments do not make the unconstrained full search practical

## Disclaimer

This project is published for **educational analysis, research, and authorized recovery testing**.

- Use it only on wallets you own or have explicit permission to test.
- Do not use it for unauthorized access attempts.
- The full 20-character Ballet-format search space is not practically brute-forceable without additional constraints.
- The author assumes no liability for misuse, damages, or legal consequences arising from unauthorized use.

By using this software, you accept responsibility for complying with all applicable laws and for ensuring that your use is authorized.

## Donate

```text
bc1qlpdkr5djv0mpz948wh2dutq48qnaazaauxxlh0
```

## License

MIT License — see [LICENSE](LICENSE) for details.
