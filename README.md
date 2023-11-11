# Rust `ring` AEAD Example

*This is intended as an educational tool, do not use in production*

This repo contains an example of how to use the `ring` crate for AES-256-GCM encryption along with a command-line REPL 
which can encrypt and decrypt string input from stdin. 

The project can be run using cargo, just use `cargo run` from the command line to start the REPL. Optionally, you
can provide your own salt and password, using the `SALT` and `PASS` environment variables, respectively.

```
Welcome to this encryption example!

Enter a command, either 'encrypt' or 'decrypt' followed by the
data to do the command on.

During encryption, the resulting data will be hex-encoded
and printed to your terminal.

During decryption, the input data will be decoded from hex
and then decrypted. The result will be printed to the terminal
in plaintext.
```
