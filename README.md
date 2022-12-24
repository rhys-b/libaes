# LibAES

A C implementation of the 128-bit Advanced Encryption Standard.

Function documentation is in `aes.h`, however the most important function is `crypt()`:

## crypt()

```c
int crypt( bool encrypt, uint8_t *data, uint32_t size, const char *password );
```

Encrypts or decrypts the data at the `data` pointer using the given password. If the `encrypt` flag is `true`, then the data is encrypted but if the flag is `false` then the data is decrypted.

**NOTE: The size of the data must be a multiple of 16 bytes. It is up to the user to decide how to make that happen.**

### Parameters:

* encrypt: If set to `true`, the data is encrypted, if set to `false`, the data is decrypted.
* data: The pointer to the data to be encrypted or decrypted.
* size: The size of the data to be encrypted or decrypted. Must be a multiple of 16.
* password: The password to use to encrypt or decrypt the data.

### Return:

* 0 if the data was able to be encrypted or decrypted (although the algorithm has no way of knowing if the password was correct).
* -1 if the size was not a multiple of 16.
