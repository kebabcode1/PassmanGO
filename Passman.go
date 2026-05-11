package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const (
	VaultFile = "vault.txt"
	MacFile   = "vault.mac"
	SaltFile  = "system.salt"
	HashFile  = "master.hash"
)

type Entry struct {
	Site  string `json:"site"`
	User  string `json:"user"`
	Pass  string `json:"pass"`
	Notes string `json:"notes"`
}

// Global inactivity timer
var lastActivity atomic.Int64

func resetTimer() {
	lastActivity.Store(time.Now().Unix())
}

func startAutoLock(key []byte) {
	resetTimer()
	go func() {
		for {
			time.Sleep(2 * time.Second)
			idle := time.Now().Unix() - lastActivity.Load()
			if idle >= 90 { // 90 seconds of inactivity
				wipeBytes(key)
				clearScreen()
				fmt.Println("\n[!] Vault locked due to inactivity (1m 30s).")
				os.Exit(0)
			}
		}
	}()
}

// Helper to wrap bufio reader and reset the auto-lock timer
func readInput(r *bufio.Reader) string {
	resetTimer()
	str, _ := r.ReadString('\n')
	resetTimer()
	return str
}

func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
}

func encrypt(plaintext string, key []byte) string {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func decrypt(ciphertext string, key []byte) string {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return ""
	}

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return ""
	}

	nonce := data[:nonceSize]
	cipherData := data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return ""
	}

	return string(plaintext)
}

func computeMAC(data []byte, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func verifyVault(key []byte) {
	vaultData, err := os.ReadFile(VaultFile)
	if err != nil {
		return
	}

	macData, err := os.ReadFile(MacFile)
	if err != nil {
		return
	}

	expected := computeMAC(vaultData, key)

	if !hmac.Equal(macData, expected) {
		fmt.Println("⚠ Vault integrity check failed!")
		os.Exit(1)
	}
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func clearScreen() {
	cmd := exec.Command("clear") // Note: Use "cmd", "/c", "cls" on Windows
	cmd.Stdout = os.Stdout
	cmd.Run()
	fmt.Print("\033[H\033[2J")
}

func getMaskedInput(prompt string) string {
	resetTimer()
	defer resetTimer()

	fmt.Print(prompt)
	fd := int(os.Stdin.Fd())

	if !term.IsTerminal(fd) {
		var pass string
		fmt.Scanln(&pass)
		return pass
	}

	state, _ := term.MakeRaw(fd)
	defer term.Restore(fd, state)

	var password []byte

	for {
		char := make([]byte, 1)
		os.Stdin.Read(char)

		if char[0] == '\r' || char[0] == '\n' {
			fmt.Println()
			break
		}

		if char[0] == 127 || char[0] == 8 {
			if len(password) > 0 {
				password = password[:len(password)-1]
				fmt.Print("\b \b")
			}
		} else if char[0] == 3 { // Ctrl+C support in raw mode
			term.Restore(fd, state)
			os.Exit(0)
		} else {
			password = append(password, char[0])
			fmt.Print("*")
		}
	}

	return string(password)
}

func generateCustomPass(length int, useUpper, useLower, useNums, useSyms bool) string {
	var chars string
	if useUpper {
		chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	if useLower {
		chars += "abcdefghijklmnopqrstuvwxyz"
	}
	if useNums {
		chars += "0123456789"
	}
	if useSyms {
		chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
	}

	// Fallback if the user declines all options
	if chars == "" {
		chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	}

	result := make([]byte, length)
	for i := range result {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		result[i] = chars[num.Int64()]
	}

	return string(result)
}

func loadVault(key []byte) []Entry {
	var entries []Entry
	data, err := os.ReadFile(VaultFile)
	if err != nil {
		return entries
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		dec := decrypt(line, key)
		var entry Entry
		err := json.Unmarshal([]byte(dec), &entry)
		if err == nil {
			entries = append(entries, entry)
		}
	}

	return entries
}

func saveVault(entries []Entry, key []byte) {
	tmp := VaultFile + ".tmp"
	f, _ := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	writer := bufio.NewWriter(f)

	for _, entry := range entries {
		data, _ := json.Marshal(entry)
		enc := encrypt(string(data), key)
		writer.WriteString(enc + "\n")
	}

	writer.Flush()
	f.Sync()
	f.Close()

	os.Rename(tmp, VaultFile)

	vaultData, _ := os.ReadFile(VaultFile)
	mac := computeMAC(vaultData, key)
	os.WriteFile(MacFile, mac, 0600)
}

func getBoolChoice(reader *bufio.Reader, prompt string) bool {
	fmt.Print(prompt)
	in := readInput(reader)
	return !strings.HasPrefix(strings.ToLower(strings.TrimSpace(in)), "n")
}

func main() {
	if _, err := os.Stat(SaltFile); os.IsNotExist(err) {
		salt := make([]byte, 16)
		rand.Read(salt)
		os.WriteFile(SaltFile, salt, 0600)
	}

	salt, _ := os.ReadFile(SaltFile)
	var key []byte

	// Master password creation block updated to require confirmation
	if _, err := os.Stat(HashFile); os.IsNotExist(err) {
		fmt.Println("Create master password")
		var pass string
		for {
			pass = getMaskedInput("Password: ")
			confirm := getMaskedInput("Confirm Password: ")

			if pass == confirm {
				break
			}
			fmt.Println("Passwords do not match. Please try again.\n")
		}

		key = deriveKey(pass, salt)
		hash := sha256.Sum256(key)
		os.WriteFile(HashFile, hash[:], 0600)
	} else {
		for {
			pass := getMaskedInput("Enter master password: ")
			key = deriveKey(pass, salt)
			hash := sha256.Sum256(key)
			stored, _ := os.ReadFile(HashFile)

			if hmac.Equal(stored, hash[:]) {
				break
			}
			fmt.Println("Incorrect password")
		}
	}

	verifyVault(key)
	startAutoLock(key) // Initialize the 90s inactivity monitor

	clearScreen()
	fmt.Println("Vault unlocked. Auto-lock set to 1m 30s of inactivity.")

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("\n(a)dd (v)iew (s)earch (e)dit (d)elete (g)enerate (q)uit : ")
		choice := strings.TrimSpace(readInput(reader))

		switch choice {

		case "q":
			wipeBytes(key)
			return

		case "g":
			fmt.Print("Length (default 16): ")
			lStr := readInput(reader)
			length := 16
			if l, err := strconv.Atoi(strings.TrimSpace(lStr)); err == nil && l > 0 {
				length = l
			}

			upper := getBoolChoice(reader, "Include uppercase? (Y/n): ")
			lower := getBoolChoice(reader, "Include lowercase? (Y/n): ")
			nums := getBoolChoice(reader, "Include numbers? (Y/n): ")
			syms := getBoolChoice(reader, "Include symbols? (Y/n): ")

			p := generateCustomPass(length, upper, lower, nums, syms)
			fmt.Println("\nGenerated:", p)
			time.Sleep(8 * time.Second)
			wipeBytes([]byte(p))
			clearScreen()

		case "a":
			fmt.Print("Site: ")
			s := readInput(reader)

			fmt.Print("User: ")
			u := readInput(reader)

			p := getMaskedInput("Password (blank to auto-generate): ")
			pass := strings.TrimSpace(p)

			if pass == "" {
				pass = generateCustomPass(16, true, true, true, true)
				fmt.Println("-> Generated strong 16-char password.")
			}

			fmt.Print("Notes: ")
			n := readInput(reader)

			entry := Entry{
				Site:  strings.TrimSpace(s),
				User:  strings.TrimSpace(u),
				Pass:  pass,
				Notes: strings.TrimSpace(n),
			}

			entries := loadVault(key)
			entries = append(entries, entry)
			saveVault(entries, key)
			fmt.Println("Saved.")

		case "v":
			entries := loadVault(key)

			if len(entries) == 0 {
				fmt.Println("Vault is empty.")
				continue
			}

			for i, e := range entries {
				notesStr := e.Notes
				if len(notesStr) > 20 {
					notesStr = notesStr[:17] + "..."
				}
				fmt.Printf("[%d] %s | %s | ******** | %s\n", i+1, e.Site, e.User, notesStr)
			}

			// Integrated reveal logic
			fmt.Print("\nEnter entry # to reveal (or press Enter to return): ")
			numStr := strings.TrimSpace(readInput(reader))

			if numStr == "" {
				continue // Go back to the main loop if they just hit Enter
			}

			idx, err := strconv.Atoi(numStr)
			if err == nil && idx > 0 && idx <= len(entries) {
				e := entries[idx-1]
				clearScreen()
				fmt.Printf("--- REVEALED ENTRY ---\nSite:  %s\nUser:  %s\nPass:  %s\nNotes: %s\n----------------------\n", e.Site, e.User, e.Pass, e.Notes)
				fmt.Println("\nScreen will automatically clear in 10 seconds...")
				time.Sleep(10 * time.Second)
				clearScreen()
			} else {
				fmt.Println("Invalid entry number.")
			}

		case "s":
			fmt.Print("Search: ")
			query := strings.ToLower(strings.TrimSpace(readInput(reader)))
			entries := loadVault(key)

			for i, e := range entries {
				if strings.Contains(strings.ToLower(e.Site), query) || strings.Contains(strings.ToLower(e.User), query) {
					notesStr := e.Notes
					if len(notesStr) > 20 {
						notesStr = notesStr[:17] + "..."
					}
					fmt.Printf("[%d] %s | %s | ******** | %s\n", i+1, e.Site, e.User, notesStr)
				}
			}

		case "e":
			entries := loadVault(key)
			for i, e := range entries {
				fmt.Printf("[%d] %s\n", i+1, e.Site)
			}

			fmt.Print("Select entry: ")
			numStr := readInput(reader)
			idx, _ := strconv.Atoi(strings.TrimSpace(numStr))

			if idx > 0 && idx <= len(entries) {
				newPass := getMaskedInput("New password (blank to keep, 'gen' to auto-generate): ")
				newPass = strings.TrimSpace(newPass)

				if newPass == "gen" {
					newPass = generateCustomPass(16, true, true, true, true)
					fmt.Println("-> Generated strong 16-char password.")
				} else if newPass == "" {
					newPass = entries[idx-1].Pass
				}

				fmt.Printf("New Notes (blank to keep current: '%s'): ", entries[idx-1].Notes)
				newNotes := strings.TrimSpace(readInput(reader))
				if newNotes == "" {
					newNotes = entries[idx-1].Notes
				}

				entries[idx-1].Pass = newPass
				entries[idx-1].Notes = newNotes
				saveVault(entries, key)
				fmt.Println("Updated.")
			}

		case "d":
			entries := loadVault(key)
			for i, e := range entries {
				fmt.Printf("[%d] %s\n", i+1, e.Site)
			}

			fmt.Print("Delete entry #: ")
			numStr := readInput(reader)
			idx, _ := strconv.Atoi(strings.TrimSpace(numStr))

			if idx > 0 && idx <= len(entries) {
				entries = append(entries[:idx-1], entries[idx:]...)
				saveVault(entries, key)
				fmt.Println("Deleted.")
			}
		}
	}
}
