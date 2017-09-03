# quandary
Stupid simple file encryption from the terminal.  

```
$> qndy
Hello!
Would you like to encrypt or decrypt a file? (e or d) e
Chose to encrypt!
Provide the path of the file you'd like to encrypt:
./file.txt
Provide the path of the file you'd like to create:
./encrypted-file.enc
Awesome! Starting to encrypt...
What's the encryption password? Your new file is located at:
./encrypted-file.enc
Goodbye!
```
*Note: The encryption / decryption password will be hidden while you type it.* 

**Dependencies:**  
- Go  

**Get Started**  
1. Clone this repository
```
git clone https://github.com/aunyks/quandary.git
```
2. Enter the newly created directory
```
cd quandary
```
3. Build the source code and create and executable
```
go build qndy.go
```
4. (Optional) Copy the newly created executable to your Path  

5. Create a new Bitcoin wallet!
```
# On macOS / Linux
./qndy
```
```
rem On Windows
start qndy.exe
```

### If you have any questions or comments, open an issue, reach out on [Twitter](https://twitter.com/aunyks), or [email me](mailto:g.nash.dev@gmail.com)!
