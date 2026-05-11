package main

import (
	"bufio"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/chaincfg"
	"golang.org/x/crypto/scrypt"
)

// ============ CONFIG ============
type Config struct {
	EncryptedPrivateKey string
	TargetAddress       string
	ConfirmationCode    string
	Mode                string
	Workers             int
	Pattern             string
}

var cfg = Config{
	EncryptedPrivateKey: "",
	TargetAddress:       "",
	ConfirmationCode:    "",
	Mode:                "random",
	Workers:             0,
	Pattern:             "XXXX-XXXX-XXXX-XXXX-XXXX",
}

const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var (
	curveOrder, _ = new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	totalTried uint64
	found      int32
	startTime  time.Time

	lastKey atomic.Value
	seqMax uint64
)

func sha256Twice(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	once := h.Sum(nil)
	h.Reset()
	h.Write(once)
	return h.Sum(nil)
}

func decodeBIP38(encryptedKey string) ([]byte, error) {
	dec := base58.Decode(encryptedKey)
	if len(dec) < 39 {
		return nil, fmt.Errorf("decoded length %d < 39", len(dec))
	}
	return dec[:39], nil
}

func publicFromPrivate(privKey []byte, compress bool) ([]byte, error) {
	privKeyInt := new(big.Int).SetBytes(privKey)
	if privKeyInt.Cmp(big.NewInt(0)) <= 0 || privKeyInt.Cmp(curveOrder) >= 0 {
		return nil, fmt.Errorf("invalid private key")
	}
	_, pubKey := btcec.PrivKeyFromBytes(privKey)
	if compress {
		return pubKey.SerializeCompressed(), nil
	}
	return pubKey.SerializeUncompressed(), nil
}

func newAddrFromPubkey(pubKey []byte, netID byte) string {
	network := &chaincfg.MainNetParams
	if netID == 0x6f {
		network = &chaincfg.TestNet3Params
	}
	addr, err := btcutil.NewAddressPubKeyHash(btcutil.Hash160(pubKey), network)
	if err != nil {
		return ""
	}
	return addr.EncodeAddress()
}

func getNetIDFromAddress(addr string) byte {
	if strings.HasPrefix(addr, "1") {
		return 0x00
	}
	if strings.HasPrefix(addr, "3") {
		return 0x05
	}
	if strings.HasPrefix(addr, "m") || strings.HasPrefix(addr, "n") {
		return 0x6f
	}
	return 0x00
}

// ============ PATTERN SYSTEM ============
type patternMask struct {
	positions       []int
	numberPositions []int
	fixed           []byte
	length          int
	xCount          int
	numberCount     int
}

var mask *patternMask

func parsePattern(pattern string) *patternMask {
    m := &patternMask{
        positions:       make([]int, 0),
        numberPositions: make([]int, 0),
        fixed:           make([]byte, len(pattern)),
        length:          len(pattern),
    }

    for i, ch := range []byte(pattern) {
        switch ch {
        case 'X', 'x':
            m.positions = append(m.positions, i)
        case '?':
            m.numberPositions = append(m.numberPositions, i)
        default:
            m.fixed[i] = ch
        }
    }
    m.xCount = len(m.positions)
    m.numberCount = len(m.numberPositions)
    return m
}

func generateFromPattern() string {
	if mask == nil {
		return ""
	}

	result := make([]byte, mask.length)
	copy(result, mask.fixed)

	var buf [32]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		panic(err)
	}

	for i, pos := range mask.positions {
		result[pos] = charset[int(buf[i%32])%len(charset)]
	}

	numCharset := "0123456789"
	for i, pos := range mask.numberPositions {
		result[pos] = numCharset[int(buf[(i+len(mask.positions))%32])%len(numCharset)]
	}

	return string(result)
}

func generateSequential(counter uint64) string {
    if mask == nil {
        return ""
    }

    result := make([]byte, mask.length)
    copy(result, mask.fixed)

    remaining := counter

    for i := 0; i < len(mask.positions); i++ {
        pos := mask.positions[i]
        result[pos] = charset[remaining%36]
        remaining /= 36
    }
    numCharset := "0123456789"
    for i := 0; i < len(mask.numberPositions); i++ {
        pos := mask.numberPositions[i]
        result[pos] = numCharset[remaining%10]
        remaining /= 10
    }

    for i := range result {
        if result[i] == 0 {
            result[i] = 'X'
        }
    }

    return string(result)
}

func calculateMaxCombinationsBig() *big.Int {
	if mask == nil {
		return big.NewInt(0)
	}
	total := new(big.Int).SetInt64(1)
	x := big.NewInt(36)
	num := big.NewInt(10)

	for i := 0; i < mask.xCount; i++ {
		total.Mul(total, x)
	}
	for i := 0; i < mask.numberCount; i++ {
		total.Mul(total, num)
	}
	return total
}
func formatWithDots(s string) string {
    n := len(s)
    if n <= 3 {
        return s
    }
    var b strings.Builder
    rem := n % 3
    if rem == 0 {
        rem = 3
    }
    b.WriteString(s[:rem])
    for i := rem; i < n; i += 3 {
        b.WriteByte('.')
        b.WriteString(s[i : i+3])
    }
    return b.String()
}
// ============ BIP38 ============
type precomputedData struct {
	ownerSalt      []byte
	ownerEntropy   []byte
	encryptedpart2 []byte
	encryptedpart1 []byte
	addrHash       []byte
	compress       bool
	hasLotSequence bool
	netID          byte
}

var precomp *precomputedData

func precompute(dec []byte, netID byte) {
    flag := dec[1]
    compress := true
    hasLotSequence := flag&0x04 == 0x04

    var ownerSalt, ownerEntropy []byte
    if hasLotSequence {
        ownerSalt = append([]byte{}, dec[7:11]...)
        ownerEntropy = append([]byte{}, dec[7:15]...)
    } else {
        ownerSalt = append([]byte{}, dec[7:15]...)
        ownerEntropy = ownerSalt
    }

    precomp = &precomputedData{
        ownerSalt:      ownerSalt,
        ownerEntropy:   ownerEntropy,
        encryptedpart2: append([]byte{}, dec[23:39]...),
        encryptedpart1: append([]byte{}, dec[15:23]...),
        addrHash:       append([]byte{}, dec[3:7]...),
        compress:       compress,
        hasLotSequence: hasLotSequence,
        netID:          netID,
    }
}

func confirmPassphraseFast(passphrase string) (bool, string) {
    if precomp == nil {
        return false, ""
    }

    prefactorA, err := scrypt.Key([]byte(passphrase), precomp.ownerSalt, 16384, 8, 8, 32)
    if err != nil {
        return false, ""
    }

    var passFactor []byte
    if precomp.hasLotSequence {
        prefactorB := append(prefactorA, precomp.ownerEntropy...)
        passFactor = sha256Twice(prefactorB)
    } else {
        passFactor = prefactorA
    }

    passpoint, err := publicFromPrivate(passFactor, true)
    if err != nil {
        return false, ""
    }

    seedbc := append(precomp.addrHash, precomp.ownerEntropy...)
    derived, err := scrypt.Key(passpoint, seedbc, 1024, 1, 1, 64)
    if err != nil {
        return false, ""
    }

    h, err := aes.NewCipher(derived[32:])
    if err != nil {
        return false, ""
    }

    unencryptedpart2 := make([]byte, 16)
    h.Decrypt(unencryptedpart2, precomp.encryptedpart2)
    for i := range unencryptedpart2 {
        unencryptedpart2[i] ^= derived[i+16]
    }

    encryptedpart1 := append(precomp.encryptedpart1, unencryptedpart2[:8]...)
    unencryptedpart1 := make([]byte, 16)
    h.Decrypt(unencryptedpart1, encryptedpart1)
    for i := range unencryptedpart1 {
        unencryptedpart1[i] ^= derived[i]
    }

    seeddb := append(unencryptedpart1[:16], unencryptedpart2[8:]...)
    factorb := sha256Twice(seeddb)

    passFactorBig := new(big.Int).SetBytes(passFactor)
    factorbBig := new(big.Int).SetBytes(factorb)
    privKey := new(big.Int).Mul(passFactorBig, factorbBig)
    privKey.Mod(privKey, curveOrder)

    privBytes := make([]byte, len(privKey.Bytes()))
    copy(privBytes, privKey.Bytes())

    pubKey, err := publicFromPrivate(privBytes, true)
    if err != nil {
        return false, ""
    }

    addr := newAddrFromPubkey(pubKey, precomp.netID)

    addrHashed := sha256Twice([]byte(addr))

    match := addrHashed[0] == precomp.addrHash[0] &&
             addrHashed[1] == precomp.addrHash[1] &&
             addrHashed[2] == precomp.addrHash[2] &&
             addrHashed[3] == precomp.addrHash[3]

    if match {
        return true, hex.EncodeToString(privBytes)
    }
    return false, ""
}

// ============ WORKERS ============
func randomWorker(id int, stop chan struct{}, result chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-stop:
			return
		default:
		}

		if atomic.LoadInt32(&found) == 1 {
			return
		}

		guess := generateFromPattern()
		atomic.AddUint64(&totalTried, 1)
		lastKey.Store(guess)

		match, privKey := confirmPassphraseFast(guess)
		if match {
			if atomic.CompareAndSwapInt32(&found, 0, 1) {
				result <- fmt.Sprintf("Passphrase: %s\nPrivate Key: %s", guess, privKey)
				close(stop)
			}
			return
		}
	}
}

func sequentialWorker(id int, totalWorkers int, stop chan struct{}, result chan<- string, wg *sync.WaitGroup) {
    defer wg.Done()
    foundCount := 0

    for counter := uint64(id); counter < seqMax; counter += uint64(totalWorkers) {
        select {
        case <-stop:
            fmt.Printf("[Worker %d] Stop received\n", id)
            return
        default:
        }

        if atomic.LoadInt32(&found) == 1 {
            fmt.Printf("[Worker %d] Found flag already set\n", id)
            return
        }

        guess := generateSequential(counter)
        atomic.AddUint64(&totalTried, 1)
        lastKey.Store(guess)

        match, privKey := confirmPassphraseFast(guess)

        if match {
            if atomic.CompareAndSwapInt32(&found, 0, 1) {
                result <- fmt.Sprintf("Passphrase: %s\nPrivate Key: %s", guess, privKey)
                close(stop)
                return
            }
        }

        foundCount++
    }
}

// ============ STATUS REPORTER ============
func statusReporter(stop <-chan struct{}) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cnt := atomic.LoadUint64(&totalTried)
			elapsed := time.Since(startTime).Seconds()
			rate := float64(cnt) / elapsed

			var last string
			if v := lastKey.Load(); v != nil {
				last = v.(string)
			}

			if cfg.Mode == "sequential" {
				percent := float64(cnt) / float64(seqMax) * 100
				fmt.Printf("\r⚡ [%.1fs] %d / %s (%.4f%%) | %.1f/s | Last: %s",
					elapsed, cnt, formatWithDots(fmt.Sprintf("%d", seqMax)), percent, rate, last)
			} else {
				fmt.Printf("\r⚡ [%.1fs] %d tested | %.1f/s | Last: %s",
					elapsed, cnt, rate, last)
			}

		case <-stop:
			fmt.Println()
			return
		}
	}
}

// ============ CONFIG ============
func loadConfig(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "EPK":
			cfg.EncryptedPrivateKey = val
		case "TARGET_ADDRESS":
			cfg.TargetAddress = val
		case "CONFIRMATION_CODE":
			cfg.ConfirmationCode = val
		case "MODE":
			cfg.Mode = val
		case "WORKERS":
			fmt.Sscanf(val, "%d", &cfg.Workers)
		case "PATTERN":
			cfg.Pattern = val
		}
	}
}

func main() {
	fmt.Println()
	fmt.Println(" +-+-+-+-+-+-+ +-+-+-+-+-+-+ +-+-+-+-+-+-+ +-+-+")
	fmt.Println(" |B|a|l|l|e|t| |W|a|l|l|e|t| |H|u|n|t|e|r| |# 1|")
	fmt.Println(" +-+-+-+-+-+-+ +-+-+-+-+-+-+ +-+-+-+-+-+-+ +-+-+")
	fmt.Println()
	fmt.Println(" 🎯 Target: 1JxWyNrkgYvgsHu8hVQZqTXEB9RftRGP5m")
	fmt.Println(" 🏆 Price:  1BTC")
	fmt.Println()
	fmt.Println(" Donate: bc1qlpdkr5djv0mpz948wh2dutq48qnaazaauxxlh0")
	fmt.Println(" By:     github.com/arturfromtheblock")
	fmt.Println()

	loadConfig("config.txt")

	if epk := os.Getenv("BIP38_EPK"); epk != "" {
		cfg.EncryptedPrivateKey = epk
	}
	if addr := os.Getenv("BIP38_TARGET"); addr != "" {
		cfg.TargetAddress = addr
	}
	if cc := os.Getenv("BIP38_CONFIRMATION"); cc != "" {
		cfg.ConfirmationCode = cc
	}
	if mode := os.Getenv("BIP38_MODE"); mode != "" {
		cfg.Mode = mode
	}
	if pattern := os.Getenv("BIP38_PATTERN"); pattern != "" {
		cfg.Pattern = pattern
	}

	if cfg.EncryptedPrivateKey == "" {
		fmt.Println("Error: EPK missing!")
		fmt.Println()
		fmt.Println("Sample config.txt:")
		fmt.Println("EPK=6PfLGnQs6VZnrN1VKPuZ8YzovfC7gB3Nqa1CZrKp5R6v1B1")
		fmt.Println("TARGET_ADDRESS=1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
		fmt.Println("CONFIRMATION_CODE=cfrm38VUGuohnUuosBHHzLjQoZ2oPTyt1tGPLsfQcKq2gXT8fkC6XJAyc4sJkXrrpy22zMVbnP5")
		fmt.Println("MODE=random")
		fmt.Println("WORKERS=0")
		fmt.Println("PATTERN=XXXX-XXXX-XXXX-XXXX-XXXX")
		fmt.Println()
		fmt.Println("Pattern-Rules:")
		fmt.Println("  X or x = random (A-Z, 0-9)")
		fmt.Println("  ?      = numbers only (0-9)")
		fmt.Println("  A-Z, 0-9, - = fixed")
		fmt.Println("  Example: ???Y-XXXX-XXXX-XXXX-XXXX")
		fmt.Println("  default: XXXX-XXXX-XXXX-XXXX-XXXX")
		fmt.Println()
		fmt.Println("Mode:")
		fmt.Println("  random     = random combinations (default)")
		fmt.Println("  sequential = systematic enumeration, only for small spaces")
		os.Exit(1)
	}

	mask = parsePattern(cfg.Pattern)
	maxComb := calculateMaxCombinationsBig()
	dec, err := decodeBIP38(cfg.EncryptedPrivateKey)
	if err != nil {
		log.Fatalf("Error while decoding: %v", err)
	}

	netID := getNetIDFromAddress(cfg.TargetAddress)
	precompute(dec, netID)

	workers := cfg.Workers
	if maxComb.Cmp(big.NewInt(1000)) < 0 && workers > 4 {
		workers = 4
	}
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	fmt.Printf("EPK:              %s\n", cfg.EncryptedPrivateKey)
	fmt.Printf("Target Address:   %s\n", cfg.TargetAddress)
	fmt.Printf("Network ID:       0x%02x\n", netID)
	fmt.Printf("Mode:             %s\n", cfg.Mode)
	fmt.Printf("Pattern:          %s\n", cfg.Pattern)
	fmt.Printf("Free Positions:   %d (X) + %d (?)\n", mask.xCount, mask.numberCount)
	fmt.Printf("Space:            %s\n", formatWithDots(maxComb.Text(10)))
	fmt.Printf("Workers:          %d\n", workers)
	fmt.Println()
	fmt.Println("⚡ Features:")
	fmt.Println("   • Pattern-Mask: X = random [A-Z & 0-9], ? = digits [0-9], - = fixed")
	fmt.Println("   • Live-Status every 250 ms with last tried key")
	fmt.Println()
	fmt.Println("⚠️  WARNING: Search space is huge!")
	fmt.Println("             Here, luck is the only thing that can help")
	fmt.Println()

	if cfg.Mode == "sequential" {
		// if !maxComb.IsUint64() {
		// 	fmt.Printf("\n❌ Search space too large for sequential mode (%.0e > 2^64-1).\n", new(big.Float).SetInt(maxComb))
		// 	fmt.Println("   Please use random mode or reduce the number of free positions.")
		// 	os.Exit(1)
		// }
		seqMax = maxComb.Uint64()
		fmt.Printf("\n📊 Sequential Mode: Testing all %s combinations\n", formatWithDots(maxComb.Text(10)))
	} else {
		fmt.Println("\n🎲 Random Mode: Testing random combinations")
	}

    startTime = time.Now()
    stop := make(chan struct{})
    result := make(chan string, 1)
    var wg sync.WaitGroup

    go statusReporter(stop)

    if cfg.Mode == "sequential" {
        for i := 0; i < workers; i++ {
            wg.Add(1)
            go sequentialWorker(i, workers, stop, result, &wg)
        }
    } else {
        for i := 0; i < workers; i++ {
            wg.Add(1)
            go randomWorker(i, stop, result, &wg)
        }
    }
    done := make(chan struct{})
    go func() {
        wg.Wait()
        close(done)
    }()

    select {
    case r := <-result:
        fmt.Println()
        fmt.Println("                                                ")
		fmt.Println("++++++++++++++++++++++++++++++++++++++++++++++++")
        fmt.Println("               🏆🏆 JACKPOT 🏆🏆                 ")
		fmt.Println("++++++++++++++++++++++++++++++++++++++++++++++++")
		fmt.Println("                                                ")
        fmt.Println(r)
        fmt.Printf("\nTime: %s\n", time.Since(startTime))
        close(stop)
    case <-done:
        close(stop)
    }

	wg.Wait()

	cnt := atomic.LoadUint64(&totalTried)
	fmt.Printf("\nTried: %d\n", cnt)
	if atomic.LoadInt32(&found) == 0 {
		fmt.Println("❌ Passphrase not found in search space.")
	}
}
