sqleet
======

**sqleet** is a public domain encryption extension for SQLite.


Compiling
---------

The code compiles with the command:

    % gcc sqleet.c shell.c -o sqleet -lpthread -ldl

On Windows, `-lpthread -ldl` are not required.

If you want to use sqleet as a library, it is recommended that you download a
preconfigured [release
package](https://github.com/resilar/sqleet/releases/latest) instead of cloning
the master.  The contained `sqleet.c` and `sqleet.h` files are intended to be
drop-in replacements for the official `sqlite3.c` amalgamation and `sqlite3.h`
header. See [SQLite3 Encryption API](#sqlite3-encryption-api) for usage
instructions.


Cryptography buzzwords
----------------------

- PBKDF2-HMAC-SHA256 key derivation algorithm with a 16-byte random salt and
  12345 iterations.
- ChaCha20 stream cipher with one-time keys.
- Poly1305 authentication tags.

A low-level description of the encryption scheme can be found in
[sqleet.c:65](sqleet.c#L65).


Example
-------

Encrypting a database with a password "swordfish".
```
[sqleet]% hexdump -C hello.db 
00000000  53 51 4c 69 74 65 20 66  6f 72 6d 61 74 20 33 00  |SQLite format 3.|
00000010  10 00 01 01 00 40 20 20  00 00 00 02 00 00 00 02  |.....@  ........|
*
00000fd0  00 00 00 2b 01 06 17 17  17 01 37 74 61 62 6c 65  |...+......7table|
00000fe0  68 65 6c 6c 6f 68 65 6c  6c 6f 02 43 52 45 41 54  |hellohello.CREAT|
*
00001fe0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 0f  |................|
00001ff0  01 02 27 48 65 6c 6c 6f  2c 20 77 6f 72 6c 64 21  |..'Hello, world!|
[sqleet]% ./sqleet hello.db
SQLite version 3.20.1 2017-08-24 16:21:36
Enter ".help" for usage hints.
sqlite> PRAGMA rekey='swordfish';
sqlite> .quit
[sqleet]% hexdump -C hello.db  
00000000  f5 85 5b cf b4 91 d1 28  f8 5c 0e da ee 7f 66 d1  |..[....(.\....f.|
00000010  55 4e 9f 71 a8 e0 8d f0  52 d8 5c 17 63 9f cc 71  |UN.q....R.\.c..q|
00000020  b3 69 9d c0 ef d1 31 5c  52 fa a3 64 47 be 65 98  |.i....1\R..dG.e.|
00000030  58 53 9c 2e db 3a ce 66  a4 d1 22 bd d2 c8 13 1b  |XS...:.f..".....|
*
```

The database can only be read with the correct password.
```
[sqleet]% ./sqleet hello.db 
SQLite version 3.20.1 2017-08-24 16:21:36
Enter ".help" for usage hints.
sqlite> .dump       
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
/**** ERROR: (26) file is not a database *****/
ROLLBACK; -- due to errors
sqlite> PRAGMA key='swordfish';
sqlite> .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE hello(x);
INSERT INTO hello VALUES('Hello, world!');
COMMIT;
```


SQLite3 encryption API
----------------------

sqleet defines `SQLITE_HAS_CODEC` at the compile time to expose SQLite3's 
`sqlite3_key()` and `sqlite3_rekey()` functions for managing encryption keys.

```c
SQLITE_API int sqlite3_key(      /* Invoked by PRAGMA key='x' */
  sqlite3 *db,                   /* Database to be rekeyed */
  const void *pKey, int nKey     /* The key (password) */
);
```

`sqlite3_key()` is typically called after `sqlite3_open()` to specify the key
for an encrypted database. Note that the function does not touch the data on
disk at all. Subsequent attempts to query the database will fail if the key was
incorrect.

```c
SQLITE_API int sqlite3_rekey(    /* Invoked by PRAGMA rekey='x' */
  sqlite3 *db,                   /* Database to be rekeyed */
  const void *pKey, int nKey     /* The new key (password) */
);
```

`sqlite3_rekey()` changes the database encryption key. This includes encrypting
the database the first time, decrypting the database (if nKey == 0), as well as
re-encrypting it with a new key. Internally, `sqlite3_rekey()` performs a
`VACUUM` to encrypt/decrypt all pages of the database.
