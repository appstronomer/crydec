# crydec

Non-commercial educational project that implements: arguments input via TTY; 
data input via `stdin` or file; data mutation using ChaCha and AES-GCM 
families of algorithms implemented by [RustCrypto](https://github.com/RustCrypto) 
team as an axample; data output into `stdout` or file.

## Usage

Checkout version and help
```sh
crydec --version
crydec --help 
```

Encrypt `src.txt` received via `stdin` to `enc` file using `--fout` cli argument. 
```sh
cat src.txt | crydec encrypt --fout enc 
```

Decrypt `enc` file using `--fin` cli argument to `dec.txt` by passing via `stdout`.
```sh
cat crydec decrypt --fin enc > dec.txt
```

Encrypt using salt `68a489eaf8fefdebf882188c502145` and nonce `7364897364773283294` 
specified via cli args. In case of specifying salt and/or nonce in any way during 
encryption you have to remember each value to specify it during decryption.
```sh
cat text.txt | crydec encrypt --salt 68a489eaf8fefdebf882188c502145 --nonce 7364897364773283294 > encrypted
```

Decrypt with memorized salt `68a489eaf8fefdebf882188c502145` and nonce 
`7364897364773283294` using tty.
```sh
cat encrypted | crydec decrypt --salt-tty --nonce-tty > decrypted.txt
```

## Priorities
1. Implement option to write random generated salt and nonce to a separate file.
2. Reveal main argon2 params as cli arguments.
3. Add missing ChaCha ciphers.
4. Unit testing.

## Inspiration
1. The will to learn memory management and encryption in Rust.
2. https://cryptography.rs/
3. https://kerkour.com/rust-file-encryption-chacha20poly1305-argon2