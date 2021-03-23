# AES Key Wrap

This library implements AES Key Wrap (RFC 3394) and AES Key Wrap with Padding
(RFC 5649).  This code was originally written before OpenSSL had support
for these algorithms.

The code made still be of use for those who implement their own AES
encryption code, but if you are using OpenSSL it probably makes more
sense to just use the OpenSSL libraries for AES Key Wrap.  See the
functions EVP_aes_128_wrap() and EVP_aes_128_wrap() and
EVP_aes_128_wrap_pad(), as examples of two ciphers that can serve in
place of the code in this library.
