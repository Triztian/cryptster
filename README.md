Cryptster
=========

A simple library to implement basic ciphers

It currently supports the ROT13 cipher (similar). Well actually it just adds 13 to the input.

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

