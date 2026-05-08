<h1 align="center">Ballet Wallet Hunter</h1>
<br>
<p align="center">
  <span>A BIP38 brute-force tool written in Go, designed to crack the **CTF Challenge** — created by Ballet Wallet founder Bobby Lee on July 31, 2020.</span>

<img src="https://raw.githubusercontent.com/arturfromtheblock/ballet-wallet-hunter/refs/heads/master/img/screen.png">

---

## What is This?

On **July 31, 2020**, the founder of Ballet Wallet launched a public Capture The Flag (CTF) challenge to demonstrate the security of Ballet's BIP38-encrypted physical Bitcoin wallets.

### The Challenge Setup

The challenge consisted of **two wallets**:

- **Wallet #1**: Contains **1 BTC** — BIP38 encrypted private key (EPK) + Confirmation Code provided. The passphrase is unknown and must be recovered.
  - **Target Address:** `1JxWyNrkgYvgsHu8hVQZqTXEB9RftRGP5m`
  - **EPK:** `6PnQmAyBky9ZXJyZBv9QSGRUXkKh9HfnVsZWPn4YtcwoKy5vufUgfA3Ld7`
  - **Confirmation Code:** `cfrm38VUGuohnUuosBHHzLjQoZ2oPTyt1tGPLsfQcKq2gXT8fkC6XJAyc4sJkXrrpy22zMVbnP5`

- **Wallet #2**: It contains 1 BTC. No EPK is provided, but the passphrase is known. This wallet shows that having the passphrase and confirmation code is useless without the EPK (encoded private key).
  - **Target:** `1QGtbKxx6FKDD66LwnrzHCAHmyZ7mDHqC4`
  - **Passphrase:** `594Y-L2RW-4ME7-2XVX-9B41`
  - **Confirmation Code:** `cfrm38VUh2i5qzzCqedWtc8ekFxT3UpcQnfb42JRrLbTWCRTfgVTCXqLp3FYxqiyQDo4D3DyWzY`

### The Passphrase Pattern

Ballet Wallet passphrases follow a specific pattern:

```
XXXX-XXXX-XXXX-XXXX-XXXX
```

Where each `X` is a character from `A-Z` or `0-9` (36 possibilities per position).

**This tool attempts to brute-force the passphrase for Wallet #1**, using optimized cryptographic operations and pattern masking to reduce the search space.

### Why This Matters

The challenge proves a critical security concept: **even if someone knows your passphrase, they cannot access your Bitcoin without the physical Ballet Wallet card** (which contains the EPK). Conversely, even if someone has your encrypted private key, they cannot decrypt it without the passphrase.

Our goal is to test the boundaries of this security model by attempting to recover the unknown passphrase through computational brute force.

## Features

- **Pattern Masking System**: Fix known characters, randomize unknown ones
  - Example: `A1XX-XXXX-B2XX-XXXX-C3XX` → only 14 positions to brute-force
- **Multi-threaded Workers**: Utilizes all CPU cores via goroutines
- **Precomputed BIP38 Data**: Eliminates redundant decoding operations
- **Fast Scrypt Path**: Optimized scrypt parameters for confirmation checks
- **Live Status Output**: Real-time rate and last-tested key display
- **Cross-platform**: Native builds for Intel and Apple Silicon Macs

## Search Space Reality Check

| Pattern                    | Positions | Search Space     | Time @ 40/s |
| -------------------------- | --------- | ---------------- | ----------- |
| `XXXX-XXXX-XXXX-XXXX-XXXX` | 20        | 36²⁰ ≈ 1.34×10³¹ | ~10²² years |
| `A1XX-XXXX-B2XX-XXXX-C3XX` | 14        | 36¹⁴ ≈ 6.14×10²¹ | ~10¹⁵ years |
| `2026-XXXX-XXXX-XXXX-XXXX` | 16        | 36¹⁶ ≈ 7.96×10²⁴ | ~10¹⁸ years |

**This tool is for educational and testing purposes. The full search space is cryptographically infeasible to brute-force without additional hints or partial passphrase knowledge.**

## Installation

### Prerequisites

- macOS (Intel or Apple Silicon)
- Go

```
# install brew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"


# install Go
brew install go
```

### Build from Source

```bash
# Clone the repository
git clone https://github.com/arturfromtheblock/ballet-wallet-hunter.git
cd ballet-wallet-hunter

# Build for your architecture
make native

# Or manually:
# Apple Silicon:
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o bwh-silicon -ldflags="-s -w" main.go

# Intel Mac:
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o bwh-intel -ldflags="-s -w" main.go

# Go
go build -o bwh -ldflags="-s -w" main.go

```

## Configuration

Create a `config.txt` file in the project directory:

```
# BIP38 Encrypted Private Key (starts with 6P)
EPK=6PfLGnQs6VZnrN1VKPuZ8YzovfC7gB3Nqa1CZrKp5R6v1B1

# Target Bitcoin address (optional, for logging)
TARGET_ADDRESS=1JxWyNrkgYvgsHu8hVQZqTXEB9RftRGP5m

# BIP38 Confirmation Code (optional, for faster verification)
CONFIRMATION_CODE= cfrm38VUGuohnUuosBHHzLjQoZ2oPTyt1tGPLsfQcKq2gXT8fkC6XJAyc4sJkXrrpy22zMVbnP5

# Search mode: "random" or "sequential"
MODE=random

# Number of workers (0 = auto-detect CPU cores)
WORKERS=0

# Passphrase pattern: X = random, anything else = fixed
# Example: A1XX-XXXX-B2XX-XXXX-C3XX
PATTERN=XXXX-XXXX-XXXX-XXXX-XXXX
```

### Environment Variables

You can also set configuration via environment variables:

```bash
export BIP38_EPK="6Pf..."
export BIP38_TARGET="1JxWy..."
export BIP38_PATTERN="A1XX-XXXX-B2XX-XXXX-C3XX"
export BIP38_WORKERS=8
./bwh-silicon
```

## Usage

```bash
# Run with config.txt
./bwh-silicon

# Expected output:
# 2026/05/08 13:33:26 [18.4s] Tried: 700 | Rate: 38.0/s | Last Key: QO2Z-A8JA-K4Z7-CRY3-BD2S
```

### Pattern Syntax

| Character    | Meaning                     |
| ------------ | --------------------------- |
| `X` or `x`   | Random character (A-Z, 0-9) |
| `A-Z`, `0-9` | Fixed character             |
| `-`          | Fixed separator             |

**Examples:**

- `XXXX-XXXX-XXXX-XXXX-XXXX` — Full random (36²⁰ combinations)
- `2026-XXXX-XXXX-XXXX-XXXX` — Year fixed, rest random (36¹⁶ combinations)
- `TEST-XXXX-XXXX-XXXX-XXXX` — Word fixed, rest random (36¹⁶ combinations)
- `A1XX-XXXX-B2XX-XXXX-C3XX` — Multiple fixed characters (36¹⁴ combinations)

## Performance Tips

1. **Use Pattern Masking**: Every fixed character reduces the search space by factor 36
2. **Native Binary**: Always use the ARM64 build on Apple Silicon (avoid Rosetta 2)
3. **CPU Priority**: Run with highest priority:
   ```bash
   nice -n -20 ./bwh-silicon
   ```
4. **Close Other Apps**: Scrypt is memory-hard and CPU-intensive

## Technical Details

### Why BIP38 is So Hard to Crack

BIP38 uses **scrypt** as its key derivation function, deliberately designed to be **memory-hard and CPU-intensive**. This makes brute-force attacks extremely expensive, even for powerful hardware.

#### Scrypt Parameters in BIP38

For each passphrase attempt, BIP38 requires **two scrypt operations**:

**Scrypt #1 (The Expensive One):**

```
scrypt(passphrase, ownerSalt, N=16384, r=8, p=8, dkLen=32)
```

**Scrypt #2 (The Fast One):**

```
scrypt(passpoint, seedbc, N=1024, r=1, p=1, dkLen=64)
```

#### What Do These Parameters Mean?

| Parameter | Value | Meaning                                                                                   |
| --------- | ----- | ----------------------------------------------------------------------------------------- |
| **N**     | 16384 | CPU/Memory cost factor. Must be a power of 2. Each doubling doubles the computation time. |
| **r**     | 8     | Block size parameter. Affects memory usage. Each doubling doubles memory consumption.     |
| **p**     | 8     | Parallelization factor. Number of parallel scrypt threads.                                |
| **dkLen** | 32    | Derived key length in bytes.                                                              |

#### Memory and Computation Cost

The total memory required for one scrypt operation is approximately:

```
Memory = 128 × N × r × p bytes
       = 128 × 16384 × 8 × 8
       = 134,217,728 bytes
       = 128 MB per operation
```

For **Scrypt #1**, this means:

- **128 MB RAM** allocated per passphrase attempt
- **Sequential memory access** pattern (cache-unfriendly)
- **~100-200 ms** per operation on modern CPUs
- Cannot be effectively parallelized on GPU due to memory constraints

#### Why GPUs Don't Help Much

Scrypt was specifically designed to resist GPU and ASIC acceleration:

1. **Memory-hard**: Requires 128 MB per thread — GPUs have limited memory per core
2. **Random access pattern**: Constant cache misses, negating GPU memory advantages
3. **Sequential dependencies**: Each block depends on the previous, limiting parallelism

A high-end GPU might achieve **2-5x** speedup over a CPU, but not the **1000x** typical for SHA-256 mining.

#### The Full BIP38 Decryption Pipeline

For each passphrase attempt:

1. **Base58-decode** the EPK → extract flags, salt, encrypted parts
2. **Scrypt #1** (expensive): Derive prefactorA from passphrase + ownerSalt
3. **SHA-256 twice**: Compute passFactor (or prefactorB + hash)
4. **EC Point Multiplication**: Compute passpoint = passFactor × G (secp256k1)
5. **Scrypt #2** (fast): Derive AES key from passpoint + address hash
6. **AES-256 Decrypt**: Decrypt encryptedpart1 and encryptedpart2
7. **SHA-256 twice**: Compute factorb from decrypted seedb
8. **EC Point Multiplication**: Compute final private key
9. **Address Generation**: Derive Bitcoin address from public key
10. **Checksum Verification**: Compare first 4 bytes with embedded hash

**Steps 2, 4, 5, and 8 are the bottlenecks.** Step 2 (scrypt N=16384) alone accounts for ~90% of the total computation time.

### Performance Reality

| Hardware                | Scrypt #1 / sec | Keys / sec | 36²⁰ search time |
| ----------------------- | --------------- | ---------- | ---------------- |
| MacBook M1 (8 cores)    | ~40             | ~40        | ~10²² years      |
| High-end CPU (16 cores) | ~80             | ~80        | ~10²² years      |
| RTX 4090 GPU            | ~200            | ~200       | ~10²¹ years      |
| Custom FPGA             | ~500            | ~500       | ~10²¹ years      |

Even with **1 million GPUs**, the search would take **~10¹⁶ years** — still vastly longer than the age of the universe (~1.38×10¹⁰ years).

### Optimizations in This Tool

- **Precomputed Data**: BIP38 decoding, salt extraction, and address hash done once
- **Pattern Masking**: Reduces search space when partial passphrase is known
- **Batch Processing**: Reduces channel overhead between goroutines
- **Atomic Counters**: Lock-free statistics tracking
- **Minimal Allocations**: Reused buffers to reduce GC pressure
- **Native Builds**: ARM64 on Apple Silicon avoids Rosetta 2 overhead

## Disclaimer

This tool is **exclusively designed for the Bobby Lee CTF Challenge** (launched July 31, 2020) and may only be used for this specific purpose.

- **Intended Use Only**: This tool is for participating in the official Ballet Wallet CTF challenge. Any other use is strictly prohibited.
- **No Misuse**: Do not use this tool to attempt cracking wallets you do not own or have explicit permission to test.
- **Cryptographic Reality**: The search space for a complete 20-character passphrase is cryptographically infeasible without additional hints or partial knowledge.
- **No Liability**: The author assumes no liability for any misuse, damages, or legal consequences arising from unauthorized use of this tool.
- **Verify First**: Always verify you have legitimate rights to attempt recovery before using this software.

By using this tool, you agree to use it solely for the Bobby Lee CTF Challenge and accept full responsibility for compliance with all applicable laws.

## Donate

```
bc1qlpdkr5djv0mpz948wh2dutq48qnaazaauxxlh0
```

## License

MIT License — see [LICENSE](LICENSE) for details.

_Happy Hunting!_ 🎯
