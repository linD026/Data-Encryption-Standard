# Data-Encryption-Standard

## How to use

```
$ make
cc -o test des.c -g  -Wall -O2
```

## Example:

* encrypt:
    ```
    $ ./test -e "test one \ two , three "
    ---
    original text (ceil size 24 bytes, size 23 bytes):

    [HEX]
    "656e6f2074736574 2c206f7774205c20 0020656572687420 "

    Encrypt text:

    [HEX]
    "5d44496ed7671f38 63cae82907dc1395 f83932ad6f8edb47 "
    [TEXT]
    "8g�nID]��)��cGێo�29�"
    ---
    ```
* decrypt:
    ```
    $ ./test -d "5d44496ed7671f38 63cae82907dc1395 f83932ad6f8edb47 "
    ---
    original text (ceil size 24 bytes, size 51 bytes):

    [HEX]
    "5d44496ed7671f38 63cae82907dc1395 f83932ad6f8edb47 "

    Decrypt text:

    [HEX]
    "656e6f2074736574 2c206f7774205c20 0020656572687420 "
    [TEXT]
    "test one \ two , three "
    ---
    ```
* encrypt then immediately decrypt (test):
    ```
    $ ./test -a "test one \ two , three "
    ---
    original text (ceil size 24 bytes, size 23 bytes):

    [HEX]
    "656e6f2074736574 2c206f7774205c20 0020656572687420 "

    Encrypt text:

    [HEX]
    "5d44496ed7671f38 63cae82907dc1395 f83932ad6f8edb47 "
    [TEXT]
    "8g�nID]��)��cGێo�29�"

    Decrypt text:

    [HEX]
    "656e6f2074736574 2c206f7774205c20 0020656572687420 "
    [TEXT]
    "test one \ two , three "

    Passed
    ---
    ```
