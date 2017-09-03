package main

import (
	"fmt"
	"os"
	"github.com/urfave/cli"
	"io/ioutil"
	"io"
	"syscall"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/crypto/pbkdf2"
	"crypto/sha256"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"bufio"
)

// Ask the user a question via stdout
// and read the response via stdin
func prompt(inquiry string) string {
	reader := bufio.NewReader(os.Stdin)
	if(inquiry[len(inquiry) - 1:] == "\n"){
		print(inquiry);
	} else {
		print(inquiry + " ");
	}
	text, _ := reader.ReadString('\n')
	return text[0 : len(text) - 1]
}

// Ask the user a question via stdout
// and read the response via stdin but hide the input
func secretPrompt(inquiry string) string {
	if(inquiry[len(inquiry) - 1:] == "\n"){
		print(inquiry);
	} else {
		print(inquiry + " ");
	}
	text, _ := terminal.ReadPassword(int(syscall.Stdin))
	return string(text)
}
  
// Something went wrong! Let the user know
// and exit immediately
func panic(mayday string) {
	println(mayday)
	os.Exit(0)
}
  
// Prompt the user with two options. Then let the calling
// process know which response was given via a boolean
// value (true is for the a value, false for the b value).
//
// If neither are provided. We panic before any more processing
// is handled
func promptABTest(inquiry string, a string, b string) bool {
	response := prompt(inquiry)
	if(response == a){
		return true
	} else if (response == b) {
		return false
	} else {
		panic("Don't understand what you said. Bye!")
	}
	return false
}

func getFileBytes(path string) []byte {
	fileBytes, err := ioutil.ReadFile(path)
	if(err != nil){
		panic("Could not read file: " + path + "\nExiting...")
	}
	return fileBytes
}

func encryptBytes(bytes []byte, password string) []byte {
	key := pbkdf2.Key([]byte(password), []byte{0x05, 0x02, 0x55, 0xd2}, 4096, 32, sha256.New)
	blockCipher, err := aes.NewCipher(key)
	if(err != nil){
		panic("Error creating encryption key! Notify @aunyks. Exiting...")
	}
	cipherBytes := make([]byte, aes.BlockSize + len(bytes))
	iv := cipherBytes[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err.Error())
	}
	stream := cipher.NewCFBEncrypter(blockCipher, iv)
	stream.XORKeyStream(cipherBytes[aes.BlockSize:], bytes)

	return cipherBytes
}

func decryptBytes(bytes []byte, password string) []byte {
	key := pbkdf2.Key([]byte(password), []byte{0x05, 0x02, 0x55, 0xd2}, 4096, 32, sha256.New)
	blockCipher, err := aes.NewCipher(key)
	if(err != nil){
		panic("Error creating decryption key! Notify @aunyks. Exiting...")
	}
	if len(bytes) < aes.BlockSize {
		panic("Input file not big enough! Is this the right file? Exiting...")
	}
	iv := bytes[:aes.BlockSize]
	bytes = bytes[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(blockCipher, iv)
	stream.XORKeyStream(bytes, bytes)

	return bytes
}

func writeFile(path string, bytes []byte) {
	if(ioutil.WriteFile(path, bytes, 0777) != nil){
		panic("Could not write to file: " + path + "\nExiting...")
	}
}

func main(){
	encrypt := false
	decrypt := false
	var inputFilePath string
	app := cli.NewApp()
	app.Name = "qndy"
	app.Version = "1.0.0"
	app.Usage = "Simple file encryption."
	app.Action = func(c *cli.Context) error {
		// Greet the user
		fmt.Println("Hello!")
		// Ask what method to use
		encryptOrDecrypt := promptABTest(
			"Would you like to encrypt or decrypt a file? (e or d)",
			"e",
			"d",
		)
		// Tell them what we received
		if(encryptOrDecrypt){
			fmt.Println("Chose to encrypt!")
			encrypt = true
		} else {
			fmt.Println("Chose to decrypt!")
			decrypt = true
		}
		// Get the input file
		if(encrypt){
			inputFilePath = prompt("Provide the path of the file you'd like to encrypt:\n")
		} else {
			inputFilePath = prompt("Provide the path of the file you'd like to decrypt:\n")
		}
		// Panic if the input file doesn't exist
		if _, err := os.Stat(inputFilePath); os.IsNotExist(err) {
			panic("The input file doesn't exist! Bye...")
		}
		// Get the output file
		outputFilePath := prompt("Provide the path of the file you'd like to create:\n")
		// Panic if the output file already exists
		if _, err := os.Stat(outputFilePath); !os.IsNotExist(err) {
			panic("The output file already exists! Bye...")
		}
		if(encrypt){
			fmt.Println("Awesome! Starting to encrypt...")
			password := secretPrompt("What's the encryption password?")
			inputFileBytes := getFileBytes(inputFilePath)
			cipherBytes := encryptBytes(inputFileBytes, password)
			writeFile(outputFilePath, cipherBytes)
		} else {
			fmt.Println("Awesome! Starting to decrypt...")
			password := secretPrompt("What's the decryption password?")
			inputFileBytes := getFileBytes(inputFilePath)
			plainBytes := decryptBytes(inputFileBytes, password)
			writeFile(outputFilePath, plainBytes)
		}
		fmt.Println("Your new file is located at:\n" + outputFilePath)
		if(decrypt) {
			fmt.Println("\nNote: If the output file doesn't function properly, it's likely that wrong password was used to decrypt.\n")
		}
		fmt.Println("Goodbye!")
		return nil
	}
	app.Run(os.Args)
}