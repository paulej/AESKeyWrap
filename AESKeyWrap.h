/*
 *  AESKeyWrap.h
 *  
 *  Copyright (C) 2015
 *  Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This file defines the function prototypes for AES Key Wrap (RFC 3394)
 *      and AES Key Wrap with Padding (RFC 5649).  Functions are provided to
 *      both perform key wrap and unwrap.
 *
 *  Portability Issues:
 *      None.
 */

#ifndef __AES_KEY_WRAP_H__
#define __AES_KEY_WRAP_H__

#include <stdint.h>                             /* For uint32_t             */

/*
 *  aes_ecb_encrypt
 *
 *  Description:
 *      This fuction performs AES encryption using ECB mode.
 *
 *  Parameters:
 *      key [in]
 *          A pointer to the key used for encryption
 *      key_length [in]
 *          The length in bits of the encryption key.  Valid values are
 *          128, 192, and 256.
 *      plaintext [in]
 *          The plaintext that is to be encrypted with the given key.
 *      plaintext_length [in]
 *          The length in octets of the plaintext paramter.  This value
 *          must be a multiple of 16 octets. (See comments.)
 *      ciphertext [out]
 *          A pointer to a buffer to hold the ciphertext.  This function does
 *          not allocate memory and expects the caller to pass a pointer
 *          to a block of memory large enough to hold the output.
 *
 *  Returns:
 *      zero (0) if successful, non-zero if there was an error.  The length
 *      of the ciphertext will be exactly the same size as the original
 *      plaintext.
 *
 *  Comments:
 *      The reason that the plaintext must be a multiple of 16 octets is
 *      that AES operates only on blocks of 16 octets.  This function has a
 *      dependency on the OpenSSL crpyto library to perform AES encryption.
 *      Note that this function will encrypt "in place", meaning the
 *      plaintext buffer and ciphertext buffers might point to the same
 *      chunk of memory.  This property is required by the key wrap function.
 *
 */
int aes_ecb_encrypt(const unsigned char *key,
                    unsigned int key_length,
                    const unsigned char *plaintext,
                    unsigned int plaintext_length,
                    unsigned char *ciphertext);

/*
 *  aes_ecb_decrypt
 *
 *  Description:
 *      This fuction performs AES decryption using ECB mode.
 *
 *  Parameters:
 *      key [in]
 *          A pointer to the key used for decryption
 *      key_length [in]
 *          The length in bits of the decryption key.  Valid values are
 *          128, 192, and 256.
 *      ciphertext [in]
 *          The ciphertext that is to be decrypted with the given key.
 *      ciphertext_length [in]
 *          The length in octets of the ciphertext paramter.  This value
 *          must be a multiple of 16 octets. (See comments.)
 *      plaintext [out]
 *          A pointer to a buffer to hold the plaintext.  This function does
 *          not allocate memory and expects the caller to pass a pointer
 *          to a block of memory large enough to hold the output.
 *
 *  Returns:
 *      Zero (0) if successful, non-zero if there was an error.  The length
 *      of the plaintext will be exactly the same size as the original
 *      ciphertext.
 *
 *  Comments:
 *      The reason that the ciphertext must be a multiple of 16 octets is
 *      that AES operates only on blocks of 16 octets.  This function has a
 *      dependency on the OpenSSL crpyto library to perform AES encryption.
 *      Note that this function will decrypt "in place", meaning the
 *      plaintext buffer and ciphertext buffers might point to the same
 *      chunk of memory.  This property is required by the key unwrap function.
 *
 */
int aes_ecb_decrypt(const unsigned char *key,
                    unsigned int key_length,
                    const unsigned char *ciphertext,
                    unsigned int ciphertext_length,
                    unsigned char *plaintext);

/*
 *  aes_key_wrap
 *
 *  Description:
 *      This performs the AES Key Wrap as per RFC 3394.
 *
 *  Parameters:
 *      key [in]
 *          A pointer to the key used for encryption.
 *      key_length [in]
 *          The length in bits of the encryption key.  Valid values are
 *          128, 192, and 256.
 *      plaintext [in]
 *          The plaintext that is to be encrypted with the given key.
 *      plaintext_length [in]
 *          The length in octets of the plaintext paramter.  This value
 *          must be a multiple of 8 octets.
 *      initialization_vector [in]
 *          The 16 octet initialization vector to use with AES Key Wrap.
 *          If this value is NULL, then the default IV will be used as per
 *          RFC 3394.
 *      ciphertext [out]
 *          A pointer to a buffer to hold the ciphertext.  This function does
 *          not allocate memory and expects the caller to pass a pointer
 *          to a block of memory large enough to hold the output.
 *      ciphertext_length [out]
 *          This is a the length of the resulting ciphertext, which will be
 *          exactly 8 octets larger than the original plaintext.
 *
 *  Returns:
 *      Zero (0) if successful, non-zero if there was an error.  The
 *      ciphertext and ciphertext_length parameters will be populated
 *      with the encrypted data and length, respectively.
 *
 *  Comments:
 *      The reason that the plaintext must be a multiple of 8 octets is
 *      that AES Key Wrap requires it (see RFC 3394).  The encryption routines
 *      expected to encrypt "in place", which AES will do.  Thus, the plaintext
 *      and ciphertext pointers are the same when attempting to encrypt data
 *      in some parts of this code.  However, callers of this function should
 *      use different pointers to memory for the ciphertext and plaintext.
 *
 */
int aes_key_wrap(   const unsigned char *key,
                    unsigned int key_length,
                    const unsigned char *plaintext,
                    unsigned int plaintext_length,
                    const unsigned char *initialization_vector,
                    unsigned char *ciphertext,
                    unsigned int *ciphertext_length);

/*
 *  aes_key_unwrap
 *
 *  Description:
 *      This performs the AES Key Unwrap as per RFC 3394.  It allows one
 *      to optionally pass a pointer to a buffer to hold the 64-bit IV.
 *      If the "initialization_vector" is provided, this will be used for
 *      integrity checking, rather than using the default value defined
 *      in RFC 3394.  Additionally, to support AES Key Wrap with Padding
 *      (RFC 5639), the "initialization_vector" should be NULL and the
 *      caller should provide a pointer to a 64-bit "integrity_data".
 *      In that case, this function will NOT perform integrity checking
 *      on the unwrapped key.
 *
 *  Parameters:
 *      key [in]
 *          A pointer to the key used for encryption.
 *      key_length [in]
 *          The length in bits of the encryption key.  Valid values are
 *          128, 192, and 256.
 *      ciphertext [in]
 *          The ciphertext that is to be decrypted with the given key.
 *      ciphertext_length [in]
 *          The length in octets of the ciphertext paramter.  This value
 *          must be a multiple of 8 octets.
 *      initialization_vector [in]
 *          The 16 octet initialization vector to use with AES Key Wrap.
 *          If this value is NULL, then the default IV will be used as per
 *          RFC 3394.  However, if "integrity_data" is not NULL, this
 *          routine will not perform an integrity check and, instead,
 *          it will populate that buffer with the integrity data for the
 *          caller to further process.
 *      plaintext [out]
 *          A pointer to a buffer to hold the plaintext.  This function does
 *          not allocate memory and expects the caller to pass a pointer
 *          to a block of memory large enough to hold the output.
 *      plaintext_length [out]
 *          This is a the length of the resulting plaintext, which will be
 *          exactly 8 octets smaller than the original ciphertext.
 *      integrity_data [out]
 *          This is a pointer to a 64-bit buffer that will contain
 *          the integrity data determined through the unwrap process.
 *          If this parameter is NULL, this function will perform integrity
 *          checking internally.  If this parameter is present, this function
 *          will not perform integrity checking and simply return the
 *          integrity data to the caller to be checked.  If both this
 *          and the initialization_vector are present, this parameter
 *          takes precedence.
 *
 *  Returns:
 *      Zero (0) if successful, non-zero if there was an error.  The
 *      plaintext and plaintext_length parameters will be populated
 *      with the decrypted data and length, respectively.  If the
 *      integrity_data parameter was not NULL, then the 64-bit integrity
 *      check register (A[] as defined in RFC 3394) will be returned to
 *      the caller without the integrity data being checked.
 *
 *  Comments:
 *      The reason that the ciphertext must be a multiple of 8 octets is
 *      that AES Key Wrap requires it (see RFC 3394).  The decryption routines
 *      expected to decrypt "in place", which AES will do.  Thus, the plaintext
 *      and ciphertext pointers are the same when attempting to encrypt data
 *      in some parts of this code.  However, callers of this function should
 *      use different pointers to memory for the ciphertext and plaintext.
 *
 */
int aes_key_unwrap( const unsigned char *key,
                    unsigned int key_length,
                    const unsigned char *ciphertext,
                    unsigned int ciphertext_length,
                    const unsigned char *initialization_vector,
                    unsigned char *plaintext,
                    unsigned int *plaintext_length,
                    unsigned char *integrity_data);

/*
 *  aes_key_wrap_with_padding
 *
 *  Description:
 *      This fuction performs the AES Key Wrap with Padding as specified in
 *      RFC 5649.
 *
 *  Parameters:
 *      key [in]
 *          A pointer to the key encrypting key (KEK).
 *      key_length [in]
 *          The length in bits of the KEK.  Valid values are 128, 192,
 *          and 256.
 *      plaintext [in]
 *          The plaintext value that is to be encrypted with the provided key.
 *      plaintext_length [in]
 *          The length in octets of the plaintext paramter.  This value
 *          must be in the range of 1 to AES_Key_Wrap_with_Padding_Max.
 *      alternative_iv [in]
 *          This is an alternative_iv vector to use.  The default value
 *          is specified in RFC 5649, but a different value may be provided.
 *          A NULL value will cause the function to use the default IV.
 *      ciphertext [out]
 *          A pointer to a buffer to hold the ciphertext.  This function does
 *          not allocate memory and expects the caller to pass a pointer
 *          to a block of memory large enough to hold the output.
 *      ciphertext_length [out]
 *          This is a the length of the resulting ciphertext.
 *
 *  Returns:
 *      Zero (0) if successful, non-zero if there was an error.
 *
 *  Comments:
 *      The encryption routines expected to encrypt "in place", which AES
 *      will do.  Thus, the plaintext and ciphertext pointers are the same
 *      when attempting to encrypt data in some parts of this code.  However,
 *      callers of this function should use different pointers to memory
 *      for the ciphertext and plaintext.
 *
 */
int aes_key_wrap_with_padding(  const unsigned char *key,
                                unsigned int key_length,
                                const unsigned char *plaintext,
                                unsigned int plaintext_length,
                                unsigned char *alternative_iv,
                                unsigned char *ciphertext,
                                unsigned int *ciphertext_length);

/*
 *  aes_key_unwrap_with_padding
 *
 *  Description:
 *      This fuction performs the AES Key Unwrap with Padding as specified in
 *      RFC 5649.
 *
 *  Parameters:
 *      key [in]
 *          A pointer to the key encryption key (KEK).
 *      key_length [in]
 *          The length in bits of the KEK.  Valid values are 128, 192,
 *          and 256.
 *      ciphertext [in]
 *          A pointer to the ciphertext to decrypt.
 *      ciphertext_length [in]
 *          This is a the length of the ciphertext.
 *      alternative_iv [in]
 *          This is an alternative_iv vector to use.  The default value
 *          is specified in RFC 5649, but a different value may be provided.
 *          A NULL value will cause the function to use the default IV.
 *      plaintext [out]
 *          A pointer to a buffer to hold the decrypted ciphertext.  This
 *          function does not allocate memory and expects the caller to pass
 *          a pointer to a block of memory large enough to hold the output.
 *      plaintext_length [out]
 *          This is a the length of the resulting plaintext.
 *
 *  Returns:
 *      Zero (0) if successful, non-zero if there was an error.
 *
 *  Comments:
 *      The decryption routines expected to decrypt "in place", which AES
 *      will do.  Thus, the plaintext and ciphertext pointers are the same
 *      when attempting to encrypt data in some parts of this code.  However,
 *      callers of this function should use different pointers to memory
 *      for the ciphertext and plaintext.
 *
 */
int aes_key_unwrap_with_padding(const unsigned char *key,
                                unsigned int key_length,
                                const unsigned char *ciphertext,
                                unsigned int ciphertext_length,
                                unsigned char *alternative_iv,
                                unsigned char *plaintext,
                                unsigned int *plaintext_length);

#endif /* __AES_KEY_WRAP_H__ */
