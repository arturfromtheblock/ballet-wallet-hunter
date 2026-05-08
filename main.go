package main

import (
	"bufio"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math"
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

	lastKey     atomic.Value
	lastKeyTime atomic.Value
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

// ============ PATTERN SYSTEM ============

type patternMask struct {
	positions []int
	fixed     []byte
	length    int
	xCount    int
}

var mask *patternMask

func parsePattern(pattern string) *patternMask {
	m := &patternMask{
		positions: make([]int, 0),
		fixed:     make([]byte, len(pattern)),
		length:    len(pattern),
	}

	for i, ch := range []byte(pattern) {
		if ch == 'X' || ch == 'x' {
			m.positions = append(m.positions, i)
		} else {
			m.fixed[i] = ch
		}
	}
	m.xCount = len(m.positions)
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

	return string(result)
}

func getSearchSpace() float64 {
	if mask == nil {
		return math.Pow(36, 20)
	}
	return math.Pow(float64(len(charset)), float64(mask.xCount))
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
}

var precomp *precomputedData

func precompute(dec []byte) {
	compress := dec[2]&0x20 == 0x20
	hasLotSequence := dec[2]&0x04 == 0x04

	var ownerSalt, ownerEntropy []byte
	if hasLotSequence {
		ownerSalt = dec[7:11]
		ownerEntropy = dec[7:15]
	} else {
		ownerSalt = dec[7:15]
		ownerEntropy = ownerSalt
	}

	precomp = &precomputedData{
		ownerSalt:      ownerSalt,
		ownerEntropy:   ownerEntropy,
		encryptedpart2: dec[23:39],
		encryptedpart1: dec[15:23],
		addrHash:       dec[3:7],
		compress:       compress,
		hasLotSequence: hasLotSequence,
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

	pubKey, err := publicFromPrivate(privKey.Bytes(), precomp.compress)
	if err != nil {
		return false, ""
	}

	addr := newAddrFromPubkey(pubKey, 0)
	addrHashed := sha256Twice([]byte(addr))

	match := addrHashed[0] == precomp.addrHash[0] && addrHashed[1] == precomp.addrHash[1] &&
		addrHashed[2] == precomp.addrHash[2] && addrHashed[3] == precomp.addrHash[3]

	if match {
		return true, hex.EncodeToString(privKey.Bytes())
	}
	return false, ""
}

// ============ WORKERS ============

func worker(id int, dec []byte, stop chan struct{}, result chan<- string, wg *sync.WaitGroup) {
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

		cnt := atomic.AddUint64(&totalTried, 1)
		if cnt%10 == 0 {
			lastKey.Store(guess)
			lastKeyTime.Store(time.Now())
		}

		match, privKey := confirmPassphraseFast(guess)
		if match {
			atomic.StoreInt32(&found, 1)
			result <- fmt.Sprintf("Passphrase: %s\nPrivate Key: %s", guess, privKey)
			close(stop)
			return
		}

		if id == 0 && cnt%100 == 0 {
		elapsed := time.Since(startTime).Seconds()
		rate := float64(cnt) / elapsed
		var last string
		if v := lastKey.Load(); v != nil {
			last = v.(string)
		}
		log.Printf("[%.1fs] Tried: %d | Rate: %.1f/s | Last Key: %s", elapsed, cnt, rate, last)
		}
	}
}

// ============ STATUS REPORTER ============


func statusReporter(stop <-chan struct{}) {
ticker := time.NewTicker(5 * time.Second)
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

   log.Printf("[%.1fs] Tried: %d | Rate: %.1f/s | Last Key: %s", elapsed, cnt, rate, last)

  case <-stop:
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
		fmt.Println("  A-Z, 0-9, - = fixed")
		fmt.Println("  default: XXXX-XXXX-XXXX-XXXX-XXXX")
		os.Exit(1)
	}

	// Pattern parsen
	mask = parsePattern(cfg.Pattern)

	dec, err := decodeBIP38(cfg.EncryptedPrivateKey)
	if err != nil {
		log.Fatalf("Error while decoding: %v", err)
	}

	precompute(dec)

	workers := cfg.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	fmt.Printf("EPK:              %s\n", cfg.EncryptedPrivateKey)
	fmt.Printf("Target Address:   %s\n", cfg.TargetAddress)
	fmt.Printf("Confirmation:     %s\n", cfg.ConfirmationCode)
	fmt.Printf("Mode:             %s\n", cfg.Mode)
	fmt.Printf("Pattern:          %s\n", cfg.Pattern)
	fmt.Printf("Free Positionss:  %d\n", mask.xCount)
	fmt.Printf("Space:            %.2e\n", getSearchSpace())
	fmt.Printf("Workers:          %d\n", workers)
	fmt.Println()
	fmt.Println("⚡ Features:")
	fmt.Println("   • Pattern-Mask: X=random, Changed=fix")
	fmt.Println("   • Live-Status every 5 seconds with the last tried key")
	fmt.Println()
	fmt.Println("⚠️  WARNING: Search space is huge!")
	fmt.Println("             Here, luck is the only thing that can help")
	fmt.Println()

	startTime = time.Now()
	stop := make(chan struct{})
	result := make(chan string, 1)
	var wg sync.WaitGroup

	// Status Reporter
	go statusReporter(stop)

	// Workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker(i, dec, stop, result, &wg)
	}

	select {
	case r := <-result:
		fmt.Println()
		fmt.Println("╔══════════════════════════════════════════════╗")
		fmt.Println("║              !!! JACKPOT !!!                 ║")
		fmt.Println("╚══════════════════════════════════════════════╝")
		fmt.Println(r)
		fmt.Printf("\nTime: %s\n", time.Since(startTime))
	// case <-time.After(24 * time.Hour):
	// 	fmt.Println("\nTimeout nach 24 Stunden")
	}

	close(stop)
	wg.Wait()

	cnt := atomic.LoadUint64(&totalTried)
	fmt.Printf("\nTried: %d\n", cnt)
}
