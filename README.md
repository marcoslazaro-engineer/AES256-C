## AES-256 in C (No External Libraries)
This is a from-scratch implementation of the AES-256 encryption algorithm in the C programming language, including user input support, and both encryption and decryption routines.
No external cryptographic libraries are used.
##PURPOSE
The goal of this project is to gain a deep understanding of how AES-256 works by building it manually, without relying on third-party libraries like OpenSSL.
This code is intended for educational purposes and cryptographic learning.
## Disclaimer
This project is for educational use only.
Do not use this implementation in production or security-critical systems.
For real-world applications, use vetted cryptographic libraries such as OpenSSL or libsodium.
## Usage
gcc -o aes256solocif aes256solocif.c
gcc -o aes256dec aes256dec.c
then 
./aes256dec and ./aes256solocif
## Author
Developed by [Marcos Lazaro Diaz ] as part of a personal project on learning and implementing cryptographic algorithms in C.
