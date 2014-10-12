Unix file encryption/decryption utility written in C.

usage: cipher [-devhs] [-p PASSWD] infile outfile

Encrypts/decrypts files with a password. If -e is supplied then the program will encrypt infile onto outfile. If -d is supplied then the reverse will happen: infile will be decrypted onto outfile. If -p is not supplied then the program will prompt for a password. -s will prompt twice for a password.
