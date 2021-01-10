API docs: <https://nickray.github.io/pkcs11-uri/pkcs11_uri/>

### Getting started

One way to generate URIs to feed into this library is the `p11tool` in GnuTLS.
Running `p11tool --list-tokens` returns the URIs for all available tokens.
Running `p11tool --list-all <token URI>` then lists all the objects in that token.
For private keys, use `GNUTLS_PIN=<pin> p11tool --login --list-all <token URI>`.

One way to create keypairs to use is with softhsm-util and pkcs11-tool:
```
softhsm2-util --init-token --free --label my-ca --pin 1234 --so-pin 1234
pkcs11-tool --module /usr/lib/libsofthsm2.so --token my-ca --login --pin 1234 --keypairgen --label my-signing-key --key-type RSA:2048
