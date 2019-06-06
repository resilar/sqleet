**sqleet** is a public domain encryption extension for
[SQLite3](https://www.sqlite.org/).

- [Compiling](#compiling)
- [Cryptography buzzwords](#cryptography-buzzwords)
- [Example](#example)
- [Library API](#library-api)
  - [C programming interface](#c-programming-interface)
  - [URI configuration interface](#uri-configuration-interface)
- [Android/iOS support](#androidios-support)
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

[Example](#example) illustrates the sqleet encryption using the compiled shell.
[Library API](#library-api) consists of [C programming
interface](#c-programming-interface) and [URI-based configuration
interface](#uri-configuration-interface).

To use sqleet as a library, the recommended way is to download a preconfigured
[release package](https://github.com/resilar/sqleet/releases/latest) instead of
cloning the source repository. Contained `sqleet.c` and `sqleet.h` files are
drop-in replacements for the original `sqlite3.c` amalgamation and `sqlite3.h`
header. Alternatively, `sqleet.c` and `sqleet.h` of the source repository can
be used directly if all sqleet source files are available at compile time.

To produce a custom release version of sqleet, run
`./script/amalgamate.sh <sqleet.c >release.c`
to create an amalgamation of SQLite3 with sqleet encryption support. Similarly,
run
`./script/amalgamate.sh <sqleet.h >release.h`
to amalgamate the header.


Cryptography buzzwords
----------------------

- PBKDF2-HMAC-SHA256 key derivation with a 16-byte salt and 12345 iterations.
- ChaCha20 stream cipher with one-time keys.
- Poly1305 authentication tags.

A low-level description of the database encryption scheme is available in
[sqleet.c:260](sqleet.c#L260).


Example
-------

Encrypting an existing database `hello.db` with a *key* (i.e., password)
`"swordfish"`.

```
[sqleet]% hexdump -C hello.db
00000000  53 51 4c 69 74 65 20 66  6f 72 6d 61 74 20 33 00  |SQLite format 3.|
00000010  10 00 01 01 00 40 20 20  00 00 00 01 00 00 00 02  |.....@  ........|
*
00000fd0  00 00 00 2b 01 06 17 17  17 01 37 74 61 62 6c 65  |...+......7table|
00000fe0  68 65 6c 6c 6f 68 65 6c  6c 6f 02 43 52 45 41 54  |hellohello.CREAT|
00000ff0  45 20 54 41 42 4c 45 20  68 65 6c 6c 6f 28 78 29  |E TABLE hello(x)|
*
00001fe0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 0f  |................|
00001ff0  01 02 27 48 65 6c 6c 6f  2c 20 77 6f 72 6c 64 21  |..'Hello, world!|
[sqleet]% ./sqleet hello.db
SQLite version 3.28.0 2019-04-16 19:49:53
Enter ".help" for usage hints.
sqlite> PRAGMA rekey='swordfish';
sqlite> .quit
[sqleet]% hexdump -C hello.db
00000000  4e 61 0c 1a 25 3f 77 1e  20 50 f4 56 61 c6 b3 37  |Na..%?w. P.Va..7|
00000010  eb aa d5 59 37 0d e6 41  1d d1 69 c8 8e 9a f5 eb  |...Y7..A..i.....|
*
00001fe0  07 79 a0 3b f1 cc 9f 7b  b2 72 11 21 28 15 71 ce  |.y.;...{.r.!(.q.|
00001ff0  e5 ad 4a cd 75 af 8e 8a  e2 79 f3 d9 2e 21 e8 4b  |..J.u....y...!.K|
```

The resulting encrypted database is accessible only with the correct key.

```
[sqleet]% ./sqleet hello.db
SQLite version 3.28.0 2019-04-16 19:49:53
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

The key can also be provided via [SQLite3 URI
filenames](https://www.sqlite.org/uri.html) instead of `PRAGMA`.

```
[sqleet]% ./sqleet 'file:hello.db?key=swordfish' 'SELECT * FROM hello'
Hello, world!
```

**Note**: \
The contents of an encrypted database file are indistinguishable from random
data of the same length. This is a conscious design decision made in sqleet,
but as a drawback, database settings cannot be read directly from the database
file. Thus, it is the user's responsibility to guarantee that the settings are
initialized properly before accessing the database. Most importantly, if the
database page size differs from the default 4096, then opening the database
will fail regardless of correct key unless the user explicitly sets `page_size`
to the proper value using `PRAGMA` command or [URI
API](#uri-configuration-interface).

In contrast, the official [SQLite Encryption Extension
(SEE)](https://www.sqlite.org/see) leaves bytes 16..23 of the database header
unencrypted so that certain information, including the page size, can be read
from encrypted databases - with the obvious cost of making database files
distinguishable from random. sqleet can optionally be compiled with
`-DSKIP_HEADER_BYTES=24` flag to get the same default behavior (bytes 0..15
contain the KDF salt so only the bytes 16..23 are actually skipped). URI
parameter `skip=n` overrides the compile-time value of `SKIP_HEADER_BYTES` with
`n`.


Library API
-----------

The public sqleet API consists of [C programming
interface](#c-programming-interface) and [URI configuration
interface](#uri-configuration-interface).


### C programming interface

sqleet defines `SQLITE_HAS_CODEC` compile-time option to expose SQLite3
encryption API, i.e., C functions `sqlite3_key()` and `sqlite3_rekey()` for
managing database encryption keys. These functions can be called directly from
C code, while other programming languages need to call the C functions via
[FFI](https://en.wikipedia.org/wiki/Foreign_function_interface) mechanism.
Another way to invoke the functions is with `PRAGMA key` and `PRAGMA rekey`
commands (see [Example](#example)).

```c
SQLITE_API int sqlite3_key(      /* Invoked by PRAGMA key='x' */
  sqlite3 *db,                   /* Database to key */
  const void *pKey, int nKey     /* Key (password) */
);
```

`sqlite3_key()` is typically called immediately after `sqlite3_open()` to
specify an encryption key (password) for the opened database. The function
validates the key by decrypting the first page of the database from disk.
Return value is `SQLITE_OK` if the given key was correct; otherwise, a non-zero
SQLite3 error code is returned and subsequent attempts to read or write the
database will fail.

```c
SQLITE_API int sqlite3_rekey(    /* Invoked by PRAGMA rekey='x' */
  sqlite3 *db,                   /* Database to rekey */
  const void *pKey, int nKey     /* New key (password) */
);
```

`sqlite3_rekey()` changes the database encryption key. This includes encrypting
the database the first time, fully decrypting the database (if `nKey == 0`), as
well as re-encrypting it with a new key. Internally, the function runs `VACUUM`
command to encrypt or decrypt all pages of the database, whereas re-encryption
with a new key is performed directly by processing each page sequentially.
Return value is `SQLITE_OK` on success and an SQLite3 error code on failure.

In addition, there are `sqlite3_key_v2()` and `sqlite3_rekey_v2()` functions
that accept name of the target database as the second parameter.


### URI configuration interface

**Disclaimer**: URI interface is experimental and subject to changes in future
versions. Use at your own risk!

Run-time configuration of sqleet encryption is implemented based on [SQLite3
URI filenames](https://www.sqlite.org/uri.html) which allow defining parameters
when opening a database. List of URI parameters supported by sqleet:

| Parameter   | Description                                                    |
| :---------- | :------------------------------------------------------------- |
| `key`       | Encryption key for `sqlite3_key()` after opening the database  |
| `salt`      | 16-byte salt for the key derivation function (KDF)             |
| `header`    | 16-byte header overwriting the database magic header (or salt) |
| `kdf`       | Key derivation function (only `none` supported for now)        |
| `skip`      | Run-time setting overriding compile-time SKIP_HEADER_BYTES     |
| `page_size` | Equivalent to `page_size` PRAGMA                               |

Hex-prefixed versions accepting a hex input string are available for parameters
`key`, `salt` and `header`.

Parameters `salt` and `header` expect 16-byte strings as inputs (shorter
strings are zero-padded to 16 bytes). The `header` string is stored in the
first 16 bytes of the database file (`header` defaults to `salt` value if
undefined). If `kdf=none`, then the default PBKDF2-HMAC-SHA256 is disabled and
`key` accepts accepts a 32-byte string that becomes the *master* encryption key
which is normally derived from the key by the KDF. This ultimately allows the
user of the library to take full control of the key derivation process.

Parameters `skip` and `page_size` override compile-time `SKIP_HEADER_BYTES`
value and `PRAGMA page_size` value, respectively.

Changing URI settings of an existing database can be accomplished with `VACUUM
INTO` (introduced in SQLite 3.27.0) by giving new URI parameter values in the
`INTO` filename. For example, `VACUUM INTO 'file:skipped.db?skip=24'` vacuums
the current main database to file `skipped.db` with `skip` set to 24. Other URI
settings, including the encryption key, are inherited from the main database
(unless `key` parameter is specified, in which case default values are used for
any unspecified parameters).

Erroneus parameters (e.g., unsupported value or otherwise bad input) cause the
opening (or vacuuming) of the database to fail with a non-zero SQLite3 error
code.


Android/iOS support
-------------------

sqleet does not have an out-of-the-box support for Android. However, [SQLite
Android Bindings](https://www.sqlite.org/android/doc/trunk/www/index.wiki)
project provides an easy way to bundle a custom SQLite3 version (such as
sqleet) into an Android application with the standard Android interface
[`android.database.sqlite`](https://developer.android.com/reference/android/database/sqlite/package-summary).
In particular, see [Using The SQLite Encryption
Extension](https://www.sqlite.org/android/doc/trunk/www/see.wiki) page for
build & usage instructions.

Likewise, sqleet does not offer an iOS version either, but compiling a custom
SQLite3 with sqleet encryption support for iOS is a straightforward task (e.g.,
compile [switflyfalling/SQLiteLib](https://github.com/swiftlyfalling/SQLiteLib)
with sqleet release amalgamation instead of the SQLite3 amalgamation).
Moreover, iOS apps with an *encrypted* WAL-journaled SQLite3 database in a
shared data container are terminated when sent to the background (see
[sqlcipher/sqlcipher#255](https://github.com/sqlcipher/sqlcipher/issues/255),
[TN2408](https://developer.apple.com/library/archive/technotes/tn2408/_index.html)
and
[TN2151](https://developer.apple.com/library/archive/technotes/tn2151/_index.html)
for more information). A common workaround is to leave the first 32 bytes of
the database file unencrypted so that iOS recognizes the file as a regular
WAL-journaled SQLite3 database and does not terminate the app. Thus, an
iOS-compatible sqleet database can be created with the following URI settings:

```
[sqleet]% ./sqleet 'file:ios.db?key=swordfish&salt=SodiumChloride42&header=SQLite%20format%203&skip=32'
SQLite version 3.28.0 2019-04-16 19:49:53
Enter ".help" for usage hints.
sqlite> CREATE TABLE f(x,y);
sqlite> .quit
[sqleet]% xxd secrets.db | head -n5
00000000: 5351 4c69 7465 2066 6f72 6d61 7420 3300  SQLite format 3.
00000010: 1000 0101 2040 2020 0000 0001 0000 0002  .... @  ........
00000020: 4640 824c 703e 3f72 dffc 3a19 23a6 c964  F@.Lp>?r..:.#..d
00000030: a1b3 abf0 8f3c 996f 0eb8 c665 afe1 0d72  .....<.o...e...r
00000040: b864 57f7 2492 8c31 6398 61d0 5d49 5a28  .dW.$..1c.a.]IZ(
```


Versioning scheme
-----------------

[sqleet releases](https://github.com/resilar/sqleet/releases/) follow a
perverse form of semantic versioning which requires some explanation. Major
version number increments indicate compatibility breaks as usual, but the minor
& patch version numbers match the targeted SQLite3 version. For instance,
sqleet v0.25.1 corresponds to SQLite v3.25.1. Although the target SQLite3
version is the primarily supported, sqleet is typically forward and backward
compatible across different SQLite3 versions without any changes to the source
code.

As a corollary, sqleet releases are published whenever a new SQLite3 version is
released. A new sqleet release thus does not necessarily include bug fixes or
new features (except updated SQLite3 version) if there has been no commits to
sqleet master branch since the previous SQLite3 release. [Releases
page](https://github.com/resilar/sqleet/releases) contains a changelog for each
sqleet release version.


License
-------

Like SQLite3, sqleet has been released in the public domain (specifically,
under the [UNLICENSE](https://unlicense.org/) license). In other words, feel
free to do whatever the fuck you want to with the code. In the unlikely case
that your country's legal system is broken with respect to public domain
software, contact `def@huumeet.info` for a custom-licensed version.
