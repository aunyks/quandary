# quandary
Stupid simple file encryption from the terminal.  

Quandary uses PBKDF2 to derive an AES-256 key that's used to encrypt a provided file, and it uses HMAC-SHA256 to detect any tampering withe ciphered file bytes.

![Quandary Example GIF](https://raw.githubusercontent.com/aunyks/quandary/master/quandary-example.gif)
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

5. Run Quandary!
```
# On macOS / Linux
./qndy
```
```
rem On Windows
start qndy.exe
```

### If you have any questions or comments, open an issue, reach out on [Twitter](https://twitter.com/aunyks), or [email me](mailto:me@aunyks.com)!
