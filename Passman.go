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
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const (
	VaultFile = "vault.txt"
	MacFile   = "vault.mac"
	SaltFile  = "system.salt"
	HashFile  = "master.hash"
	WaitTime  = 1 * time.Minute
)

type Entry struct {
	Site string `json:"site"`
	User string `json:"user"`
	Pass string `json:"pass"`
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

	cmd := exec.Command("clear")
	cmd.Stdout = os.Stdout
	cmd.Run()

	fmt.Print("\033[H\033[2J")
}

func getMaskedInput(prompt string) string {

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

		} else {

			password = append(password, char[0])
			fmt.Print("*")

		}
	}

	return string(password)
}

func generateSecurePass(length int) string {

	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"

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

func main() {

	if _, err := os.Stat(SaltFile); os.IsNotExist(err) {

		salt := make([]byte, 16)
		rand.Read(salt)

		os.WriteFile(SaltFile, salt, 0600)
	}

	salt, _ := os.ReadFile(SaltFile)

	var key []byte

	if _, err := os.Stat(HashFile); os.IsNotExist(err) {

		fmt.Println("Create master password")

		pass := getMaskedInput("Password: ")

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

	clearScreen()

	fmt.Println("Vault unlocked")

	reader := bufio.NewReader(os.Stdin)

	for {

		fmt.Print("\n(a)dd (v)iew (s)earch (e)dit (d)elete (g)enerate (q)uit : ")

		input, _ := reader.ReadString('\n')

		choice := strings.TrimSpace(input)

		switch choice {

		case "q":

			wipeBytes(key)

			return

		case "g":

			p := generateSecurePass(18)

			fmt.Println("Generated:", p)

			time.Sleep(8 * time.Second)

			wipeBytes([]byte(p))

			clearScreen()

		case "a":

			fmt.Print("Site: ")
			s, _ := reader.ReadString('\n')

			fmt.Print("User: ")
			u, _ := reader.ReadString('\n')

			p := getMaskedInput("Password(blank to generate): ")

			pass := strings.TrimSpace(p)

			if pass == "" {
				pass = generateSecurePass(16)
			}

			entry := Entry{
				Site: strings.TrimSpace(s),
				User: strings.TrimSpace(u),
				Pass: pass,
			}

			entries := loadVault(key)

			entries = append(entries, entry)

			saveVault(entries, key)

			fmt.Println("Saved")

		case "v":

			entries := loadVault(key)

			for i, e := range entries {

				fmt.Printf("[%d] %s | %s | %s\n", i+1, e.Site, e.User, e.Pass)

			}

			time.Sleep(10 * time.Second)

			clearScreen()

		case "s":

			fmt.Print("Search: ")

			query, _ := reader.ReadString('\n')

			query = strings.ToLower(strings.TrimSpace(query))

			entries := loadVault(key)

			for i, e := range entries {

				if strings.Contains(strings.ToLower(e.Site), query) ||
					strings.Contains(strings.ToLower(e.User), query) {

					fmt.Printf("[%d] %s | %s | %s\n", i+1, e.Site, e.User, e.Pass)

				}
			}

		case "e":

			entries := loadVault(key)

			for i, e := range entries {
				fmt.Printf("[%d] %s\n", i+1, e.Site)
			}

			fmt.Print("Select entry: ")

			numStr, _ := reader.ReadString('\n')

			idx, _ := strconv.Atoi(strings.TrimSpace(numStr))

			if idx > 0 && idx <= len(entries) {

				newPass := getMaskedInput("New password(blank=gen): ")

				if strings.TrimSpace(newPass) == "" {
					newPass = generateSecurePass(16)
				}

				entries[idx-1].Pass = newPass

				saveVault(entries, key)

				fmt.Println("Updated")
			}

		case "d":

			entries := loadVault(key)

			for i, e := range entries {
				fmt.Printf("[%d] %s\n", i+1, e.Site)
			}

			fmt.Print("Delete entry #: ")

			numStr, _ := reader.ReadString('\n')

			idx, _ := strconv.Atoi(strings.TrimSpace(numStr))

			if idx > 0 && idx <= len(entries) {

				entries = append(entries[:idx-1], entries[idx:]...)

				saveVault(entries, key)

				fmt.Println("Deleted")
			}

		}
	}
}
