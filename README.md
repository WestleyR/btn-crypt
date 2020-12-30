# BTN-crypt

Better-then-nothing encryption/decryption.

The `btn_crypt.h` file provides a simple, high level interface for basic file
encryption. It is a single, portable C header/source file, and the only dependency
is `stdio.h`.

**WARNING:** This code should only be used for reference. If you really need encryption
you should use a real encryption algorithm.

## Using the example cli interface

This project includes an example cli interface. You first need to compile it:

```
git clone https://github.com/WestleyR/btn-crypt
cd btn-crypt/
make

./btnc --help
```

