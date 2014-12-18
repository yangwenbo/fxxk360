##Recover origin ELF from protected one##
```
gcc recoverELF.c -o recoverELF -lcrypto -lz
```
1. Fix the corrupted ELF headers. 
2. Dump the real ELF in specific section(.upx.1) using RC4.
3. Recover the real ELF By deriving RC4 key from .text section, uncompress the rest part of .text and decrypt the .rotext using RC4.

##Recover origin DEX from protected one##
```
gcc recoverDex.c LzmaDec.c -o recoverDex -lcrypto
```
1. Locate the padding part in DEX and parse it to get some parameters such as RC4 key, data length, etc. 
2. Decrypt and lzma decode the padding part. 
3. Decrypt the headers of the padding to recover the headers of DEX.
