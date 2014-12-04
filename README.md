Cryptster
=========

A simple library to implement basic ciphers

It currently supports the ROT13 cipher (similar). Well actually it just adds 13 to the input.

Repo: https://github.com/Triztian/cryptster

## Usage

### Ciphering a string

```
$ cryptster -c "ROT13" -t "Hello"
```

### Ciphering the file content
```
$ cryptster -c "ROT13" -f "file-with-content.txt"
```

### Ciphering a string and writing the ciphertext into a file

```
$ cryptster -c "ROT13" -t "Hello" -o "my-secret-file.rot13"
```

### Unciphering a string
```
$ cryptster -d -c "ROT13" -t "Uryy|"
```

### Unciphering a file
```
$ cryptster -d -c "ROT13" -f "my-secret-file.rot13" 
```

## Symmetric Key Ciphering
### AES (Rijndael)
To use the AES encryption you should provide a 16 char length key string.
```
$ cryptster -k "1234567890abcdef" -c AESCBC128 -t "My secret message" 
```
