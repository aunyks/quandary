package main

import (
	"errors"
	"io"
	"io/ioutil"
	"os"

	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"

	"github.com/urfave/cli"
)

const (
	SaltBytesLength  = 32
	HashBytesLength  = 32
	AESKeySize       = 32
	NumKDFIterations = 4096
)

// Something went wrong! Let the user know
// and exit immediately
func panic(mayday string) {
	println(mayday)
	os.Exit(1)
}

func fileExists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

func getFileBytes(path string) []byte {
	fileBytes, err := ioutil.ReadFile(path)
	if err != nil {
		panic("Could not read file: " + path + "\nExiting...")
	}
	return fileBytes
}

// HmacHash generates a HMAC-SHA256 using the provided message bytes and key bytes
func HmacHash(bytes []byte, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(bytes)
	return mac.Sum(nil)
}

func hmacAssertVerification(firstHash []byte, secondHash []byte) {
	if !hmac.Equal(firstHash, secondHash) {
		panic("\nError in decryption! Either the file was tampered with or the decryption password was incorrect.")
	}
}

// PasswordEncrypt encrypts the provided plaintext bytes using the provided password
func PasswordEncrypt(bytes []byte, password string) ([]byte, error) {
	passKey := []byte(password)
	return EncryptBytes(bytes, passKey)
}

// EncryptBytes encrypts the provided plaintext bytes using AES-256 under the CFB mode of operation.
// the ciphertext is also tagged with a HMAC-SHA256
func EncryptBytes(bytes []byte, passKey []byte) ([]byte, error) {
	// Generate salt
	salt := make([]byte, SaltBytesLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, errors.New("Error generating salt")
	}
	// Create encryption key
	key := pbkdf2.Key(passKey, salt, NumKDFIterations, AESKeySize, sha256.New)
	// Create block cipher
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("Error creating encryption key")
	}
	// Allocate block cipher
	cipherBytes := make([]byte, aes.BlockSize+len(bytes))
	// Create random initialization vector
	iv := cipherBytes[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	// Encrypt and store ciphered bytes
	stream := cipher.NewCFBEncrypter(blockCipher, iv)
	stream.XORKeyStream(cipherBytes[aes.BlockSize:], bytes)

	// Use encryption key to generate hmac hash
	// of encrypted bytes
	hash := HmacHash(cipherBytes, key)

	// Store the salt with the encrypted bytes and hash
	return append(append(salt, cipherBytes...), hash...), nil
}

// PasswordDecrypt decrypts the provided plaintext bytes using the provided password
func PasswordDecrypt(bytes []byte, password string) ([]byte, error) {
	passKey := []byte(password)
	return DecryptBytes(bytes, passKey)
}

// DecryptBytes decrypts the provided plaintext bytes using AES-256 under the CFB mode of operation.
func DecryptBytes(bytes []byte, passKey []byte) ([]byte, error) {
	// Extract salt
	salt := bytes[:SaltBytesLength]
	// Generate decryption key
	key := pbkdf2.Key(passKey, salt, NumKDFIterations, AESKeySize, sha256.New)
	// Check the message for tampering or incorrect password
	hash := bytes[len(bytes)-HashBytesLength:]
	hmacAssertVerification(hash, HmacHash(bytes[SaltBytesLength:len(bytes)-HashBytesLength], key))
	// If success, create new cipher
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("Error creating decryption key")
	}
	if len(bytes) < aes.BlockSize {
		return nil, errors.New("Input file not large enough")
	}
	// Extract initialization vector and get bytes
	iv := bytes[:aes.BlockSize]
	bytes = bytes[aes.BlockSize:]
	// Decrypt the bytes
	stream := cipher.NewCFBDecrypter(blockCipher, iv)
	stream.XORKeyStream(bytes, bytes)
	// Return decrypted bytes and ignore salt
	return bytes[SaltBytesLength : len(bytes)-HashBytesLength], nil
}

func writeFile(path string, bytes []byte) {
	if ioutil.WriteFile(path, bytes, 0777) != nil {
		panic("Could not write to file: " + path + "\nExiting...")
	}
}

func main() {
	var plaintextFilepath string
	var ciphertextFilepath string
	var outputFilepath string
	var password string
	app := cli.NewApp()
	app.Name = "qndy"
	app.Version = "2.1.0"
	app.Usage = "Simple file encryption."
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "encrypt, e",
			Usage:       "Encrypt the specified file",
			Destination: &plaintextFilepath,
		},
		cli.StringFlag{
			Name:        "decrypt, d",
			Usage:       "Decrypt the specified file",
			Destination: &ciphertextFilepath,
		},
		cli.StringFlag{
			Name:        "password, p",
			Usage:       "The encryption/decryption password",
			Destination: &password,
		},
		cli.StringFlag{
			Name:        "output, o",
			Usage:       "The output filepath",
			Destination: &outputFilepath,
		},
	}
	app.Action = func(c *cli.Context) error {
		if plaintextFilepath != "" && ciphertextFilepath != "" {
			panic("Cannot encrypt and decrypt simultaneously!")
		}
		if plaintextFilepath == "" && ciphertextFilepath == "" {
			panic("A file must be encrypted or decrypted!")
		}
		if outputFilepath == "" {
			panic("An output file path must be specified!")
		}
		if fileExists(outputFilepath) {
			panic("The output file already exists!")
		}
		if plaintextFilepath != "" {
			if password == "" {
				panic("An encryption password must be provided!")
			}
			inputFilePath := plaintextFilepath
			if !fileExists(inputFilePath) {
				panic("Input file doesn't exist!")
			}
			inputFileBytes := getFileBytes(inputFilePath)
			cipherText, encryptionErr := PasswordEncrypt(inputFileBytes, password)
			if encryptionErr != nil {
				panic("Error while encrypting file!")
			} else {
				writeFile(outputFilepath, cipherText)
			}
		} else {
			if password == "" {
				panic("A decryption password must be provided!")
			}
			inputFilePath := ciphertextFilepath
			if !fileExists(inputFilePath) {
				panic("Input file doesn't exist!")
			}
			inputFileBytes := getFileBytes(inputFilePath)
			plaintextBytes, decryptionErr := PasswordDecrypt(inputFileBytes, password)
			if decryptionErr != nil {
				panic("Error while decrypting file!")
			} else {
				writeFile(outputFilepath, plaintextBytes)
			}
		}
		return nil
	}
	app.Run(os.Args)
}
