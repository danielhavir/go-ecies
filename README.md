# Elliptic Curve Integrated Encryption Scheme

## Description
This is an ECIES Go implementation, a hybrid asymmetric–symmetric key encryption
algorithm based on the Diffie–Hellman key exchange, specifically uses one of the following combinations:
1. Mode P256
    * P-256 curve (FIPS 186-3, section D.2.3)
    * AES-128 for symmetric encryption with the CTR (Counter) mode
    * Poly1305 for message aunthentication (MAC with 32-bit key with length of 16bytes, i.e. 128 bits)
    * SHA-256 for hashing and key-derivation function
2. Mode P521
    * P-521 curve (FIPS 186-3, section D.2.5)
    * AES-256 for symmetric encryption with the CTR (Counter) mode
    * Poly1305 for message aunthentication (MAC with 32-bit key with length of 16bytes, i.e. 128 bits)
    * SHA-512 for hashing and key-derivation function

## Setup

### Install Go
See [the installation script](https://gist.github.com/danielhavir/d8df1a260a2c042a01c48303ca3967c7)

### Uninstall Go
See [the uninstallation script](https://gist.github.com/danielhavir/d8df1a260a2c042a01c48303ca3967c7)

### Build without Go Modules (Go before 1.11)

```
export GO111MODULE=off ;# you might need this to disable module for recent Go versions

go get golang.org/x/crypto ;# included Poly1305 MAC

go get github.com/danielhavir/go-ecies ;# grab go-ecies

go build -o ~/go/bin/ecies github.com/danielhavir/go-ecies ;# install as ~/go/bin/ecies

# remember to add ~/go/bin to your env var PATH: PATH=$PATH:$HOME/go/bin
```

### Build with Go Modules (Go 1.11 and later)

```
git clone https://github.com/danielhavir/go-ecies
cd go-ecies
go test ./ecies ;# run tests
go install ./cmd/ecies ;# install as ~/go/bin/ecies

# remember to add ~/go/bin to your env var PATH: PATH=$PATH:$HOME/go/bin
```

## Run
* Run `ecies -en -in=<input_file> -out=<output_file> -pub=<path_to_public_key>` for encryption
* Run `ecies -de -in=<input_file> -out=<output_file> -prv=<path_to_private_key>` for decryption
* Optionally, you can also:
    * Use `-mode` to specify whether to use curve P-521 with AES-256 and SHA-512 (`-mode=P521`) or P-256 with AES-128 and SHA-256 (`-mode=P256`). SHA-512 or SHA-256 only applies to hashing, for MAC, Poly1305 is used in both cases.
    * Use the `-hex` flag to _encode encrypted ciphertext_ to hex encoding, or _decode ciphertext_ for decription from hex encoding. **IMPORTANT** You must specify the same mode for both encryption and decryption, otherwise, you will encounter "Incorrect public key" error.
    * Use the `-generate-key-pair` flag to generate new pair of private and public key. In such case, `-prv` and `-pub` specify the path for the generate private key, respectively public key
* Alternatively, you can run: `ecies -generate-key-pair -mode=<P256||P521> -prv=<output_private_key_path>  -pub=<output_public_key_path>` to generate new key pair

### Default options
* `-mode`: P256
* `-hex`: False
* `-generate-key-pair`: False
* `-prv`: key.pem
* `-pub`: key.pub
* `-in`: file.txt
* `-out`: out.out

### Examples
* `ecies -en -in=file.txt -out=out.out -generate-key-pair -hex -mode=P521` generates new private and public key storred as _key.pem_ and _key.pub_ encrypts file.txt to hexadecimal out.out using mode P521.
* `ecies -de -in=out.out -out=decrypted.txt -hex -mode=P521` decrypts hexadecimal out.out into decrypted.txt using default _key.pem_ (public key not required for decryption).
* `ecies -generate-key-pair -prv=p256-key.pem -pub=p256-key.pub` generates new key pair for EC P-256 and saves the keys in "p256-key.pem" and "p256-key.pub".

### Help
* For more info run `ecies -h`

## References
* Aumasson, J.P. - Serious Cryptography: A Practical Introduction to Modern Encryption
* Gayoso Martínez, Víctor & Hernandez Encinas, Luis & Sánchez Ávila, Carmen. (2010). A Survey of the Elliptic Curve Integrated Encryption Scheme. Journal of Computer Science and Engineering. 2. 7-13. Downloaded [here](https://www.researchgate.net/publication/255970113_A_Survey_of_the_Elliptic_Curve_Integrated_Encryption_Scheme)
* [Integrated Encryption Scheme (Wikipedia)](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme#Formal_description)

## Reference implementations
* [Ethereum ECIES implementation](https://github.com/ethereum/go-ethereum/tree/master/crypto/ecies)
