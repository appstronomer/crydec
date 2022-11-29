# crydec

Non-commercial educational project that implements: arguments input via TTY; 
data input via `stdin` or file; data mutation using ChaCha and AES-GCM 
families of algorithms implemented by [RustCrypto](https://github.com/RustCrypto) 
team as an axample; data output into `stdout` or file.

## Usage

Checkout version and help
```sh
crydec --version && crydec --help 
```

Encrypt `src.txt` received via `stdin` to `enc` file using `--fout` cli argument. 
In this case all encryption params (cipher type, salt, nonce, etc.) will be saved 
in ciphertext header.
```sh
cat src.txt | crydec encrypt --fout enc 
```

Decrypt `enc` file using `--fin` cli argument to `dec.txt` via `stdout`.
```sh
crydec decrypt --fin enc > dec.txt
```

Encrypt and decrypt using salt `68a489eaf8fefdebf882188c502145ec` and nonce 
`7364897364773283294` specified via cli args. You may set salt and nonce over tty
by using `--salt` and `--nonce` flags. All encryption config will be saved 
to `enc.spec` file instead of ciphertext header due to `--fspec` argument. You 
have to provide the same spec file during decryption.
```sh
cat src.txt | cargo run -- encrypt --salt-cli 68a489eaf8fefdebf882188c502145ec --nonce-cli 7364897364773283294 --fspec enc.spec > enc
cat enc | cargo run -- decrypt --fspec enc.spec > dec.txt
```

Multiple encryption and decryption with different ciphers using linux piping.
```sh
cat src.txt | crydec encrypt | crydec encrypt --cipher aes256-gcm | crydec encrypt --cipher aes128-gcm > enc
cat enc | crydec decrypt | crydec decrypt | crydec decrypt > dec.txt
```

## Priorities
- [x] Implement option to write random generated salt and nonce to a separate file.
- [x] Reveal main argon2 params as cli arguments.
- [x] Add missing ChaCha ciphers.
- [ ] Unit tests.
- [ ] Prevent rand::OsRng panic probability somehow.

## Inspiration
- The will to learn memory management and encryption in Rust.
- https://cryptography.rs/
- https://kerkour.com/rust-file-encryption-chacha20poly1305-argon2
