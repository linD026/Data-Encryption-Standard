# Data-Encryption-Standard

## How to use

```
$ make
cc -o test des.c -g  -Wall -O2
```

## Example:

* encrypt:
    ```
    $ ./test -e "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    original text (ceil size 48 bytes, size 46 bytes):
    
    hex: "6161616161616161 6161616161616161 6161616161616161 6161616161616161 6161616161616161 616161616161 "
    
    Encrypt text:
    hex: "10af0c6997ba0af9 10af0c6997ba0af9 10af0c6997ba0af9 10af0c6997ba0af9 10af0c6997ba0af9 c5a4eb5557b78264 "
    text: "�
    ��i
       ��
    ��i
       ��
    ��i
       ��
    ��i
       ��
    ��i
       �d��WU��"
    ```
* decrypt:
    ```
    $ ./test -d "10af0c6997ba0af9 10af0c6997ba0af9 10af0c6997ba0af9 10af0c6997ba0af9 10af0c6997ba0af9 c5a4eb5557b78264 "
    original text (ceil size 48 bytes, size 102 bytes):
    
    hex: "10af0c6997ba0af9 10af0c6997ba0af9 10af0c6997ba0af9 10af0c6997ba0af9 10af0c6997ba0af9 c5a4eb5557b78264 "
    
    Decrypt text:
    hex: "6161616161616161 6161616161616161 6161616161616161 6161616161616161 6161616161616161 616161616161 "
    text: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ```
* encrypt then immediately decrypt (test):
    ```
    $ ./test -a "aaaaaaaaaaasasaaaaaaaaaaaasasasasasdadasdasdasd"
    original text (ceil size 48 bytes, size 47 bytes):
    
    hex: "6161616161616161 6161736173616161 6161616161616161 6173617361736161 7361646164736173 64736164736164 "
    
    Encrypt text:
    hex: "10af0c6997ba0af9 d7d08ad9b759c188 10af0c6997ba0af9 1d7167c778886b2f 3a6d449fb881667c 10462f239cfe954c "
    text: "�
    ��i
       ���Y�ي���
    ��i
       �/k�x�gq|f���Dm:L���#/F"
    
    Decrypt text:
    hex: "6161616161616161 6161736173616161 6161616161616161 6173617361736161 7361646164736173 64736164736164 "
    text: "aaaaaaaaaaasasaaaaaaaaaaaasasasasasdadasdasdasd"
    
    Passed
    ```
