# quandary
Stupid simple file encryption from the terminal.  

Quandary uses PBKDF2 to derive an AES-256 key that's used to encrypt a provided file, and it uses HMAC-SHA256 to detect any tampering withe ciphered file bytes.

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
3. Build the executable
```
go build -o $GOPATH/bin/qndy
```  

5. Run Quandary and see your options!
```
# On macOS / Linux
qndy -h
```
```
rem On Windows
qndy -h
```

### If you have any questions or comments, open an issue, reach out on [Twitter](https://twitter.com/aunyks), or [email me](mailto:me@aunyks.com)!

Copyright (c) 2017-2019 Gerald Nash  
Licensed under the GNU General Public License Version 3 (GPLv3)
