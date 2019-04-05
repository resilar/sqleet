#define SQLITE3_H_OMIT
#include "sqleet.h"
#include "sqlite3.c"
#include "rekeyvacuum.c"
#include "crypto.c"

/*
 * SQLite3 codec implementation.
 */
typedef struct codec { 
    void *pagebuf;
    int pagesize;
    struct codec *reader, *writer;
    unsigned char key[32], saltbuf[16], headerbuf[16];
    unsigned char *salt, *header;
    int error;
    const void *zKey;
    int nKey;
    int skip;
    enum { KDF_NONE = 0, KDF_PBKDF2_HMAC_SHA256 } kdf;
} Codec;

Codec *codec_new(const char *zKey, int nKey, Btree *pBt)
{
    Codec *codec;
    if ((codec = sqlite3_malloc(sizeof(Codec)))) {
        codec->pagesize = sqlite3BtreeGetPageSize(pBt);
        if ((codec->pagebuf = sqlite3_malloc(codec->pagesize))) {
            codec->reader = codec->writer = codec;
            codec->salt = codec->header = NULL;
            codec->error = SQLITE_OK;
            codec->zKey = zKey;
            codec->nKey = nKey;
            /* Remaining fields initialized by codec_parse_uri_config() */
        } else {
            sqlite3_free(codec);
            codec = NULL;
        }
    }
    return codec;
}

Codec *codec_dup(Codec *src, Btree *pBt)
{
    Codec *codec;
    if ((codec = codec_new(src->zKey, src->nKey, pBt))) {
        codec->reader = (src->reader == src) ? codec : src->reader;
        codec->writer = (src->writer == src) ? codec : src->writer;

        memcpy(codec->key, src->key, sizeof(codec->key));
        if (src->salt) {
            memcpy(codec->saltbuf, src->salt, sizeof(codec->saltbuf));
            codec->salt = codec->saltbuf;
        }
        if (src->header) {
            memcpy(codec->headerbuf, src->header, sizeof(codec->headerbuf));
            codec->header = codec->headerbuf;
        }

        codec->skip = src->skip;
        codec->kdf = src->kdf;
    }
    return codec;
}

void codec_free(void *pcodec)
{
    if (pcodec) {
        int i;
        volatile char *p;
        Codec *codec = pcodec;
        if ((p = codec->pagebuf)) {
            for (i = 0; i < codec->pagesize; p[i++] = '\0');
            sqlite3_free(codec->pagebuf);
        }
        for (i = 0, p = pcodec; i < sizeof(Codec); p[i++] = '\0');
        sqlite3_free(codec);
    }
}

static int codec_uri_parameter(const char *zUri, const char *parameter,
                               size_t len_min, size_t len_max,
                               unsigned char *out)
{
    int rc;
    size_t len;
    const char *val, *hex;
    char localbuf[256], *buf;

    /* Get hex-prefixed URI query parameter value */
    len = strlen(parameter);
    buf = (len < sizeof(localbuf) - 3) ? localbuf : sqlite3_malloc(3 + len + 1);
    if (!buf) return SQLITE_NOMEM;
    buf[0] = 'h'; buf[1] = 'e'; buf[2] = 'x';
    memcpy(buf+3, parameter, len+1);
    hex = sqlite3_uri_parameter(zUri, buf);
    if (buf != localbuf)
        sqlite3_free(buf);

    /* Parse parameter value of length len_min..len_max bytes */
    if (!len_max)
        len_max = len_min;
    if ((val = sqlite3_uri_parameter(zUri, parameter))) {
        /* Copy a non-hex value string */
        if (!hex && (len = strlen(val)) >= len_min && len <= len_max) {
            if (len)
                memcpy(out, val, len);
            if (len < len_max)
                memset(&out[len], 0, len_max - len);
            rc = SQLITE_OK;
        } else {
            rc = SQLITE_MISUSE;
        }
    } else if (hex) {
        /* Decode hex digits */
        size_t i;
        for (i = 0; i < 2*len_max && hex[i]; i++) {
            char c = hex[i];
            if (c >= '0' && c <= '9') {
                c = c - '0';
            } else if (c >= 'A' && c <= 'F') {
                c = c - 'A' + 10;
            } else if (c >= 'a' && c <= 'f') {
                c = c - 'a' + 10;
            } else {
                break;
            }
            out[i/2] = (out[i/2] << 4) | c;
        }
        if (!hex[i] && 2*len_min <= i) {
            if  (i & 1) {
                out[i/2] <<= 4;
                i++;
            }
            for (i = i/2; i < len_max; out[i++] = '\0');
            rc = SQLITE_OK;
        } else {
            rc = SQLITE_MISUSE;
        }
    } else {
        /* Parameter undefined */
        rc = SQLITE_NOTFOUND;
    }

    return rc;
}

int codec_parse_uri_config(Codec *codec, Btree *pBt)
{
    int rc, pagesize;
    const char *param, *zUri = sqlite3BtreeGetFilename(pBt);
    memset(codec->key, 0, sizeof(codec->key));
    memset(codec->saltbuf, 0, sizeof(codec->saltbuf));
    memset(codec->headerbuf, 0, sizeof(codec->headerbuf));
    codec->salt = codec->header = NULL;

    /* Override page_size PRAGMA */
    pagesize = sqlite3BtreeGetPageSize(pBt);
    pagesize = sqlite3_uri_int64(zUri, "pagesize", pagesize);
    pagesize = sqlite3_uri_int64(zUri, "page_size", pagesize);
    if (pagesize && pagesize != codec->pagesize) {
        void *pagebuf;
        if (pagesize < 512 || pagesize > 65536 || (pagesize & (pagesize-1)))
            return SQLITE_MISUSE;

        if (!(pagebuf = sqlite3_malloc(pagesize)))
            return SQLITE_NOMEM;

        if ((rc = sqlite3BtreeSetPageSize(pBt, pagesize, -1, 0)) != SQLITE_OK) {
            sqlite3_free(pagebuf);
            return rc;
        } else {
            int i;
            volatile char *p;
            i = (pagesize < codec->pagesize) ? pagesize : codec->pagesize;
            memcpy(pagebuf, codec->pagebuf, i);
            for (i = 0, p = codec->pagebuf; i < codec->pagesize; p[i++] = '\0');
            sqlite3_free(codec->pagebuf);
            codec->pagebuf = pagebuf;
            codec->pagesize = pagesize;
        }
    }

    /* Override compile-time SKIP_HEADER_BYTES setting */
    codec->skip = sqlite3_uri_int64(zUri, "skip", SKIP_HEADER_BYTES);

    /* Override key derivation function (KDF) */
    if ((param = sqlite3_uri_parameter(zUri, "kdf"))) {
        if (strcmp(param, "none") != 0 || codec->nKey != sizeof(codec->key))
            return SQLITE_MISUSE;
        codec->kdf = KDF_NONE;
    } else {
        codec->kdf = KDF_PBKDF2_HMAC_SHA256;
    }

    /* KDF salt of length 0..16 */
    rc = codec_uri_parameter(zUri, "salt", 0, sizeof(codec->saltbuf),
                            codec->saltbuf);
    if (rc == SQLITE_OK) {
        codec->salt = codec->saltbuf;
    } else if (rc != SQLITE_NOTFOUND) {
        return rc;
    }

    /* File header of length 0..16 */
    rc = codec_uri_parameter(zUri, "header", 0, sizeof(codec->headerbuf),
                             codec->headerbuf);
    if (rc == SQLITE_OK) {
        if (codec->salt || codec->kdf == KDF_NONE) {
            codec->header = codec->headerbuf;
        } else {
            /* Salt required in addition to header when using KDF */
            rc = SQLITE_MISUSE;
        }
    } else if (rc == SQLITE_NOTFOUND) {
        if (codec->kdf == KDF_NONE) {
            /*
             * Salt is optional when KDF is disabled. In this case, the skipping
             * of the header encryption is also applied to SQLite3 magic string.
             */
            if (codec->skip) {
                memcpy(codec->headerbuf, "SQLite format 3",
                       (codec->skip < 16) ? codec->skip : 16);
            }
            if (codec->skip < 16)
                chacha20_rng(&codec->headerbuf[codec->skip], 16 - codec->skip);
            codec->header = codec->headerbuf;
        }
        rc = SQLITE_OK;
    }

    return rc;
}

void codec_kdf(Codec *codec)
{
    if (!codec->salt) {
        chacha20_rng(codec->saltbuf, sizeof(codec->saltbuf));
        codec->salt = codec->saltbuf;
    }
    if (!codec->header)
        codec->header = codec->salt;

    if (codec->kdf == KDF_PBKDF2_HMAC_SHA256) {
        pbkdf2_hmac_sha256(codec->zKey, codec->nKey,
                           codec->salt, sizeof(codec->saltbuf),
                           12345,
                           codec->key, sizeof(codec->key));
    } else /*if (codec->kdf == KDF_NONE)*/ {
        memcpy(codec->key, codec->zKey, sizeof(codec->key));
    }

    codec->zKey = NULL;
    codec->nKey = 0;
}

/*
 * The encrypted database page format.
 *
 * +----------------------------------------+----------------+----------------+
 * | Encrypted data                         | 16-byte nonce  | 16-byte tag    |
 * +----------------------------------------+----------------+----------------+
 *
 * As the only exception, the first page (page_no=1) starts with a plaintext
 * salt contained in the first 16 bytes of the database file. The "master" key
 * is derived from a user-given password with the salt and 12345 iterations of
 * PBKDF-HMAC-SHA256. Future plans include switching to BLAKE2 and Argon2.
 *
 * - The data is encrypted by XORing with the ChaCha20 keystream produced from
 *   the 16-byte nonce and a 32-byte encryption key derived from the master key.
 *   - OK, I lied a little: ChaCha20 uses only the first 12 bytes as the nonce.
 *     However, ChaCha20 also requires an initial value for a counter of 4 bytes
 *     that encodes a block position in the output stream. We derive the counter
 *     value from the last 4 bytes, effectively extending the nonce to 16 bytes.
 *   - Specifically, counter = LOAD32_LE(nonce[12..15])^page_no is first applied
 *     to generate a single 64-byte block from nonce[0..11] and the master key.
 *     The block consists of two 32-byte one-time keys, the former is a Poly1305
 *     key for the authentication tag, and the latter is a ChaCha20 key for the
 *     data encryption. The encryption with the one-time key uses nonce[0..11]
 *     and the initial counter value of counter+1.
 *   - The XOR with page_no prevents malicious reordering of the pages.
 *
 * - The nonce consists of 128 randomly generated bits, which should be enough
 *   to guarantee uniqueness with a secure pseudorandom number generator.
 *   - Given a secure PRNG, the adversary needs to observe at least 2^61 nonces
 *     to break Poly1305 with the birthday attack at a success rate of 1%.
 *   - If a nonce is reused, we lose confidentiality of the associated messages.
 *     Moreover, the compromised nonce can also be used to forge valid tags for
 *     new messages having the same nonce (basically, the one-time Poly1305 key
 *     can be recovered from distinct messages with identical nonces).
 *
 * - The tag is a Poly1305 MAC calculated over the encrypted data and the nonce
 *   with the one-time key generated from the master key and the nonce.
 */
#define PAGE_NONCE_LEN 16
#define PAGE_TAG_LEN 16
#define PAGE_RESERVED_LEN (PAGE_NONCE_LEN + PAGE_TAG_LEN)
void *codec_handle(void *codec, void *pdata, Pgno page, int mode)
{
    uint32_t counter;
    unsigned char otk[64], tag[16], *data = pdata;
    Codec *reader = ((Codec *)codec)->reader;
    Codec *writer = ((Codec *)codec)->writer;

    switch (mode) {
    case 0: /* Journal decryption */
    case 2: /* Reload a page */
    case 3: /* Load a page */
        if (reader) {
            const int n = reader->pagesize - PAGE_RESERVED_LEN;
            const int skip = (page == 1) ? reader->skip : 0;
            if (page == 1 && reader->zKey) {
                if (!reader->salt) {
                    memcpy(reader->saltbuf, data, 16);
                    reader->salt = reader->saltbuf;
                }
                codec_kdf(reader);
            }

            /* Generate one-time keys */
            memset(otk, 0, 64);
            counter = LOAD32_LE(data + n + PAGE_NONCE_LEN-4) ^ page;
            chacha20_xor(otk, 64, reader->key, data + n, counter);

            /* Verify the MAC */
            poly1305(data, n + PAGE_NONCE_LEN, otk, tag);
            if (poly1305_tagcmp(data + n + PAGE_NONCE_LEN, tag) != 0) {
                reader->error = SQLITE_AUTH;
                return NULL;
            }

            /* Decrypt */
            chacha20_xor(data + skip, n - skip, otk+32, data + n, counter+1);
            if (page == 1) memcpy(data, "SQLite format 3", 16);
        }
        break;

    case 7: /* Encrypt a journal page (with the reader key) */
        writer = reader;
        /* fall-through */
    case 6: /* Encrypt a main database page */
        if (writer) {
            const int n = writer->pagesize - PAGE_RESERVED_LEN;
            const int skip = (page == 1) ? writer->skip : 0;
            data = memcpy(writer->pagebuf, data, writer->pagesize);

            /* Generate one-time keys */
            memset(otk, 0, 64);
            chacha20_rng(data + n, 16);
            counter = LOAD32_LE(data + n + PAGE_NONCE_LEN-4) ^ page;
            chacha20_xor(otk, 64, writer->key, data + n, counter);

            /* Encrypt and authenticate */
            chacha20_xor(data + skip, n - skip, otk+32, data + n, counter+1);
            if (page == 1) memcpy(data, writer->header, 16);
            poly1305(data, n + PAGE_NONCE_LEN, otk, data + n + PAGE_NONCE_LEN);
        }
        break;
    }

    return data;
}

/* Verify encryption key by reading page1 (and triggering KDF) */
static int verify_page1(Pager *pager)
{
    int rc, count;
    sqlite3PagerSharedLock(pager);
    sqlite3PagerPagecount(pager, &count);
    if (count > 0) {
        /* Non-empty database, read page1 */
        DbPage *page;
        sqlite3PcacheTruncate(pager->pPCache, 0);
        if ((rc = sqlite3PagerGet(pager, 1, &page, 0)) == SQLITE_OK) {
            /* Validate the read database header */
            rc = SQLITE_NOTADB;
            if (!memcmp(page->pData, "SQLite format 3", 16)) {
                unsigned char *data = page->pData;
                int pagesize = (data[16] << 8) | data[17];
                if (pagesize >= 512 && !(pagesize & (pagesize-1))) {
                    if (data[21] == 64 && data[22] == 32 && data[23] == 32)
                        rc = SQLITE_OK;
                }
            }
            sqlite3PagerUnref(page);
        } else {
            Codec *codec = sqlite3PagerGetCodec(pager);
            if (codec && codec->error != SQLITE_OK)
                rc = codec->error;
            sqlite3PagerSetCodec(pager, NULL, NULL, NULL, NULL);
        }
    } else {
        /* Empty database */
        Codec *codec = sqlite3PagerGetCodec(pager);
        if (codec && codec->zKey) {
            /* Derive a new key */
            codec_kdf(codec);
        }
        rc = SQLITE_OK;
    }
    pager_unlock(pager);
    return rc;
}

/*
 * Set (or unset) a codec for a Btree pager.
 * The passed in codec is consumed by the function.
 */
static int codec_set_to(Codec *codec, Btree *pBt)
{
    Pager *pager = sqlite3BtreePager(pBt);
    if (codec) {
        /* Force secure delete */
        sqlite3BtreeSecureDelete(pBt, 1);

        /* Adjust the page size and the reserved area */
        if (pager->nReserve != PAGE_RESERVED_LEN) {
            pBt->pBt->btsFlags &= ~BTS_PAGESIZE_FIXED;
            sqlite3BtreeSetPageSize(pBt, codec->pagesize, PAGE_RESERVED_LEN, 0);
        }

        /* Set pager codec and try to read page1 */
        sqlite3PagerSetCodec(pager, codec_handle, NULL, codec_free, codec);
    } else {
        /* Unset a codec */
        sqlite3PagerSetCodec(pager, NULL, NULL, NULL, NULL);
    }
    return verify_page1(pager);
}

void sqlite3CodecGetKey(sqlite3 *db, int nDb, void **zKey, int *nKey)
{
    /*
     * sqlite3.c calls this function to decide if a database attached without a
     * password should use the encryption scheme of the main database. Returns
     * *nKey == 1 to indicate that the main database encryption is available.
     */
    *zKey = NULL;
    *nKey = !!sqlite3PagerGetCodec(sqlite3BtreePager(db->aDb[nDb].pBt));
}

int sqlite3CodecAttach(sqlite3 *db, int nDb, const void *zKey, int nKey)
{
    int rc;
    Codec *codec;
    Btree *pBt = db->aDb[nDb].pBt;

    rc = SQLITE_NOMEM;
    sqlite3_mutex_enter(db->mutex);
    if (!nKey) {
        /* Attach with an empty key (no encryption) */
        rc = codec_set_to(NULL, pBt);
    } else if (zKey) {
        /* Attach with the provided key */
        if ((codec = codec_new(zKey, nKey, pBt))) {
            if ((rc = codec_parse_uri_config(codec, pBt)) == SQLITE_OK) {
                if (codec->salt)
                    codec_kdf(codec);
                rc = codec_set_to(codec, pBt);
            } else {
                codec_free(codec);
            }
        } else {
            rc = SQLITE_NOMEM;
        }
    } else if (nDb != 0) {
        /* Use the main database's codec */
        codec = sqlite3PagerGetCodec(sqlite3BtreePager(db->aDb[0].pBt));
        if (codec && (codec = codec_dup(codec, pBt))) {
            rc = codec_set_to(codec, pBt);
        } else {
            rc = SQLITE_CANTOPEN;
        }
    }
    sqlite3_mutex_leave(db->mutex);
    return rc;
}

/* Returns the main database if there is no match */
static int db_index_of(sqlite3 *db, const char *zDbName)
{
    int i;
    if (zDbName) {
        for (i = 0; i < db->nDb; i++) {
            if (!strcmp(db->aDb[i].zDbSName, zDbName))
                return i;
        }
    }
    return 0;
}

int sqlite3_key_v2(sqlite3 *db, const char *zDbName, const void *zKey, int nKey)
{
    return sqlite3CodecAttach(db, db_index_of(db, zDbName), zKey, nKey);
}

int sqlite3_key(sqlite3 *db, const void *zKey, int nKey)
{
    return sqlite3_key_v2(db, "main", zKey, nKey);
}

int sqlite3_rekey_v2(sqlite3 *db, const char *zDbName,
                     const void *zKey, int nKey)
{
    char *err;
    int nDb, rc;
    Btree *pBt;

    if (!db || (!nKey && !zKey))
        return SQLITE_ERROR;

    sqlite3_mutex_enter(db->mutex);
    if ((pBt = db->aDb[(nDb = db_index_of(db, zDbName))].pBt)) {
        Pgno pgno;
        DbPage *page;
        Codec *reader, *codec;
        Pager *pager = sqlite3BtreePager(pBt);

        reader = sqlite3PagerGetCodec(pager);
        if (!nKey) {
            /* Decrypt */
            if (reader) {
                reader->writer = NULL;
                rc = sqlite3RekeyVacuum(&err, db, nDb, NULL, 0);
                if (rc == SQLITE_OK) {
                    rc = codec_set_to(NULL, pBt);
                } else {
                    reader->writer = reader->reader;
                }
            } else {
                rc = verify_page1(pager);
            }
            goto leave;
        }

        /* Create a codec for the new key */
        if ((codec = codec_new(zKey, nKey, pBt))) {
            if ((rc = codec_parse_uri_config(codec, pBt)) == SQLITE_OK) {
                codec_kdf(codec);
            } else {
                codec_free(codec);
                goto leave;
            }
        } else {
            rc = SQLITE_NOMEM;
            goto leave;
        }

        if (!reader) {
            /* Encrypt */
            codec->reader = NULL;
            if ((rc = codec_set_to(codec, pBt)) == SQLITE_OK) {
                rc = sqlite3RekeyVacuum(&err, db, nDb, NULL, PAGE_RESERVED_LEN);
                if (rc == SQLITE_OK) {
                    codec->reader = codec->writer;
                } else {
                    sqlite3PagerSetCodec(pager, NULL, NULL, NULL, NULL);
                }
            }
            goto leave;
        }

        /* Change key (re-encrypt) */
        reader->writer = codec;
        rc = sqlite3BtreeBeginTrans(pBt, 1, NULL);
        for (pgno = 1; rc == SQLITE_OK && pgno <= pager->dbSize; pgno++) {
            /* The DB page occupied by the PENDING_BYTE is never used */
            if (pgno == PENDING_BYTE_PAGE(pager))
                continue;
            if ((rc = sqlite3PagerGet(pager, pgno, &page, 0)) == SQLITE_OK) {
                rc = sqlite3PagerWrite(page);
                sqlite3PagerUnref(page);
            }
        }
        if (rc == SQLITE_OK) {
            sqlite3BtreeCommit(pBt);
            rc = codec_set_to(codec, pBt);
        } else {
            reader->writer = reader;
            sqlite3BtreeRollback(pBt, SQLITE_ABORT_ROLLBACK, 0);
        }
    } else {
        /* Btree of the specified database is NULL */
        rc = SQLITE_INTERNAL;
    }

leave:
    sqlite3_mutex_leave(db->mutex);
    return rc;
}

int sqlite3_rekey(sqlite3 *db, const void *zKey, int nKey)
{
    return sqlite3_rekey_v2(db, "main", zKey, nKey);
}

void sqlite3_activate_see(const char *info)
{
}
