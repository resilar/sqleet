**sqleet** is a public domain encryption extension for
[SQLite3](https://www.sqlite.org/).

- [Compiling](#compiling)
- [Cryptography buzzwords](#cryptography-buzzwords)
- [Example](#example)
- [SQLite3 encryption API](#sqlite3-encryption-api)
- [Android support](#android-support)
- [Remarks](#remarks)
- [Versioning scheme](#versioning-scheme)
- [License](#license)

Compiling
---------

SQLite3 shell with sqleet encryption support can be compiled as follows:

```sh
    % # UNIX
    % gcc sqleet.c shell.c -o sqleet -lpthread -ldl

    % # Windows
    % gcc sqleet.c shell.c -o sqleet
```

[Example](#example) illustrates sqleet encryption using the compiled shell.

To use sqleet as a library, the recommended way is to download a preconfigured
[release package](https://github.com/resilar/sqleet/releases/latest) instead of
cloning the master. The contained `sqleet.c` and `sqleet.h` files are drop-in
replacements for the official `sqlite3.c` amalgamation and `sqlite3.h` header.
The C interface of the sqleet encryption extension is described in section
[SQLite3 encryption API](#sqlite3-encryption-api).


Cryptography buzzwords
----------------------

- PBKDF2-HMAC-SHA256 key derivation algorithm with a 16-byte random salt and
  12345 iterations.
- ChaCha20 stream cipher with one-time keys.
- Poly1305 authentication tags.

A low-level description of the encryption scheme is available in
[sqleet.c:91](sqleet.c#L91).


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

If the target database has a non-default page size (i.e., other than 4096),
then `page_size` must be initialized accordingly with `PRAGMA` before setting
the encryption key. See [Remarks](#remarks) for more information.


SQLite3 encryption API
----------------------

sqleet defines `SQLITE_HAS_CODEC` at the compile time to expose SQLite3's 
`sqlite3_key()` and `sqlite3_rekey()` functions for managing encryption keys.

```c
SQLITE_API int sqlite3_key(      /* Invoked by PRAGMA key='x' */
  sqlite3 *db,                   /* Database to key */
  const void *pKey, int nKey     /* Key (password) */
);
```

`sqlite3_key()` is typically called immediately after `sqlite3_open()` to
specify an encryption key for the opened database. The function returns
`SQLITE_OK` if the given key was correct; otherwise, a non-zero SQLite3 error
code is returned and subsequent attempts to read or write the database will
fail. Note that the first page of the database is read from the disk in order
to validate the key.

```c
SQLITE_API int sqlite3_rekey(    /* Invoked by PRAGMA rekey='x' */
  sqlite3 *db,                   /* Database to rekey */
  const void *pKey, int nKey     /* New key (password) */
);
```

`sqlite3_rekey()` changes the database encryption key. This includes encrypting
the database the first time, decrypting the database (if nKey == 0), as well as
re-encrypting it with a new key. Internally, `sqlite3_rekey()` performs a
`VACUUM` to encrypt/decrypt all pages of the database. The return value is
`SQLITE_OK` on success and a SQLite3 error code on failure.


Android support
---------------

sqleet does not have an out-of-the-box support for Android. However, [SQLite
Android Bindings](https://www.sqlite.org/android/doc/trunk/www/index.wiki)
project provides an easy way to bundle a custom SQLite3 version (such as
sqleet) into an Android application with the standard Android interface
[`android.database.sqlite`](https://developer.android.com/reference/android/database/sqlite/package-summary).
In particular, see [Using The SQLite Encryption
Extension](https://www.sqlite.org/android/doc/trunk/www/see.wiki) page for
build & usage instructions.


Remarks
-------

The contents of an encrypted database file are indistinguishable from random
data of the same length. This is a conscious design decision made in sqleet,
but as a drawback, database settings cannot be read directly from the database
file. Thus, it is the user's responsibility to guarantee that the settings are
initialized properly before accessing the database. Most importantly, if the
database page size differs from the default value of 4096, then the user must
explicitly set `page_size` to the actual value (using, e.g., `PRAGMA` command)
or otherwise opening the database will fail regardless of correct key.

In contrast, the official [SQLite Encryption Extension
(SEE)](https://www.sqlite.org/see) leaves the bytes 16 through 23 of the
database header unencrypted so that specific information, including the page
size, can be read from encrypted databases - with the obvious cost of making
database files distinguishable from random. sqleet can optionally be compiled
with the same behavior by giving `-DSKIP_HEADER_BYTES=24` flag at compile time
(the value 24 only skips the encryption of the bytes 16 through to 23 because
the first 16 bytes contain a plaintext salt anyway).


Versioning scheme
-----------------

[sqleet releases](https://github.com/resilar/sqleet/releases/) follow a
perverse form of semantic versioning which requires some explanation. Major
version number increments indicate compatibility breaks as usual, but the minor
& patch version numbers match the targeted SQLite3 version. For example, sqleet
v0.25.1 corresponds to SQLite v3.25.1. Although the target SQLite3 version is
the primarily supported, sqleet is typically forward and backward compatible
across different SQLite3 versions without any changes to the source code.


License
-------

Like SQLite3, sqleet has been released in the public domain (specifically,
under the [UNLICENSE](https://unlicense.org/) license). In other words, feel
free to do whatever the fuck you want to with the code. In the unlikely case
that your country's legal system is broken with respect to public domain
software, contact `def@huumeet.info` for a custom-licensed version.
