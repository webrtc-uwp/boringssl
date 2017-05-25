/* ====================================================================
 * Copyright (c) 2002-2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ==================================================================== */

#ifdef OPENSSL_USE_BCRYPT

#include <openssl/aes.h>

#include <assert.h>
#include <stdlib.h>

#include <openssl/cpu.h>
#include <openssl/mem.h>

#include "internal.h"

#include <Windows.h>
#include <bcrypt.h>

struct aes_key_bcrypt_st
{
  BCRYPT_ALG_HANDLE hAesAlg;
  BCRYPT_KEY_HANDLE hKey;
  PBYTE pbKeyObject;
  DWORD cbKeyObject;
  DWORD cbBlockLength;
};

#define NT_IS_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

int AES_set_encrypt_key(const uint8_t *key, unsigned bits, AES_KEY *aeskey) {

  int result = -3;

  struct aes_key_bcrypt_st *bcrypt = NULL;
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  DWORD    cbData = 0;
#if 0
  BCRYPT_KEY_DATA_BLOB_HEADER *blobHeader = NULL;
#endif /* 0 */
  ULONG keyBytes = (bits / 8) + (bits % 8 == 0 ? 0 : 1);

  if (!aeskey) {
    return -1;
  }

  aeskey->bcrypt = (struct aes_key_bcrypt_st *)OPENSSL_malloc(sizeof(struct aes_key_bcrypt_st));
  if (NULL == aeskey->bcrypt) {
    goto Failure;
  }

  aeskey->bcrypt->hAesAlg = NULL;
  aeskey->bcrypt->hKey = NULL;
  aeskey->bcrypt->pbKeyObject = NULL;
  aeskey->bcrypt->cbKeyObject = 0;

  if (!key) {
    return -1;
  }

  switch (bits) {
  case 128:
    aeskey->rounds = 10;
    break;
  case 192:
    aeskey->rounds = 12;
    break;
  case 256:
    aeskey->rounds = 14;
    break;
  default:
    return -2;
  }

  // Open an algorithm handle.
  if (!NT_IS_SUCCESS(status = BCryptOpenAlgorithmProvider(
    &(aeskey->bcrypt->hAesAlg),
    BCRYPT_AES_ALGORITHM,
    NULL,
    0)))
  {
    /* wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status); */
    goto Failure;
  }

  if (!NT_IS_SUCCESS(status = BCryptSetProperty(aeskey->bcrypt->hAesAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0)))
  {
    /* wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status); */
    goto Failure;
  }

  if (!NT_IS_SUCCESS(status = BCryptGetProperty(
    aeskey->bcrypt->hAesAlg,
    BCRYPT_BLOCK_LENGTH,
    (PBYTE)&(aeskey->bcrypt->cbBlockLength),
    sizeof(DWORD),
    &cbData,
    0)))
  {
    /* wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status); */
    goto Failure;
  }

  if (AES_BLOCK_SIZE != aeskey->bcrypt->cbBlockLength)
  {
    assert(0);
    goto Failure;
  }

  // Calculate the size of the buffer to hold the KeyObject.
  if (!NT_IS_SUCCESS(status = BCryptGetProperty(
    aeskey->bcrypt->hAesAlg,
    BCRYPT_OBJECT_LENGTH,
    (PBYTE)&(aeskey->bcrypt->cbKeyObject),
    sizeof(DWORD),
    &cbData,
    0)))
  {
    /* wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status); */
    goto Failure;
  }

  aeskey->bcrypt->pbKeyObject = (PBYTE)OPENSSL_malloc(aeskey->bcrypt->cbKeyObject);
  if (NULL == aeskey->bcrypt->pbKeyObject)
  {
    /* wprintf(L"**** memory allocation failed\n"); */
    goto Failure;
  }

#if 0
  blobHeader = (BCRYPT_KEY_DATA_BLOB_HEADER *)OPENSSL_malloc(sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + keyBytes);
  if (NULL == blobHeader) {
    goto Failure;
  }

  blobHeader->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
  blobHeader->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
  blobHeader->cbKeyData = keyBytes;
  memcpy(&(((PBYTE)blobHeader)[sizeof(BCRYPT_KEY_DATA_BLOB_HEADER)]), key, keyBytes);
#endif /* 0 */

  if (!NT_IS_SUCCESS(status = BCryptGenerateSymmetricKey(aeskey->bcrypt->hAesAlg, &(aeskey->bcrypt->hKey), aeskey->bcrypt->pbKeyObject, aeskey->bcrypt->cbKeyObject, (PUCHAR)key, keyBytes, 0))) {
    goto Failure;
  }

#if 0
  if (!NT_IS_SUCCESS(status = BCryptImportKey(
    aeskey->bcrypt->hAesAlg,
    NULL, /* _In_opt_ BCRYPT_KEY_HANDLE hImportKey, */
    BCRYPT_KEY_DATA_BLOB,
    &(aeskey->bcrypt->hKey),
    aeskey->bcrypt->pbKeyObject,
    aeskey->bcrypt->cbKeyObject,
    (PUCHAR)blobHeader,
    sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + keyBytes,
    0 /* _In_ ULONG dwFlags */
  )))
  {
    goto Failure;
  }
#endif /* 0 */

  result = 0;
  goto Cleanup;

Failure:
  {
    AES_clean_key(aeskey);
    goto Cleanup;
  }

Cleanup:
  {
#if 0

    if (NULL != blobHeader) {
      OPENSSL_free(blobHeader);
      blobHeader = NULL;
    }
#endif /* 0 */
  }

  return result;
}

int AES_set_decrypt_key(const uint8_t *key, unsigned bits, AES_KEY *aeskey)
{
  return AES_set_encrypt_key(key, bits, aeskey);
}

void AES_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  ULONG result = 0;

  assert(in && out && key);

  if (!NT_IS_SUCCESS(status = BCryptEncrypt(key->bcrypt->hKey, (PUCHAR)in, (ULONG)(key->bcrypt->cbBlockLength), NULL, NULL, 0, (PUCHAR)out, (ULONG)(key->bcrypt->cbBlockLength), &result, 0))) {
    assert(0);
  }
}

void AES_decrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  ULONG result = 0;

  assert(in && out && key);

  if (!NT_IS_SUCCESS(status = BCryptDecrypt(key->bcrypt->hKey, (PUCHAR)in, (ULONG)(key->bcrypt->cbBlockLength), NULL, NULL, 0, (PUCHAR)out, (ULONG)(key->bcrypt->cbBlockLength), &result, 0))) {
    assert(0);
  }
}

void AES_clean_key(AES_KEY *aeskey)
{
  if (!aeskey) return;
  if (!(aeskey->bcrypt)) return;

  if (NULL != (aeskey->bcrypt->hKey))
  {
    BCryptDestroyKey(aeskey->bcrypt->hKey);
    aeskey->bcrypt->hKey = NULL;
  }
  if (NULL != aeskey->bcrypt->pbKeyObject)
  {
    /* NOTE: Can only be done after cleaning the key object */
    memset(aeskey->bcrypt->pbKeyObject, 0, aeskey->bcrypt->cbKeyObject);
    OPENSSL_free(aeskey->bcrypt->pbKeyObject);
    aeskey->bcrypt->pbKeyObject = NULL;
    aeskey->bcrypt->cbKeyObject = 0;
  }
  if (NULL != (aeskey->bcrypt->hAesAlg))
  {
    BCryptCloseAlgorithmProvider(aeskey->bcrypt->hAesAlg, 0);
    aeskey->bcrypt->hAesAlg = NULL;
  }

  OPENSSL_free(aeskey->bcrypt);
  aeskey->bcrypt = NULL;
}

#endif /* OPENSSL_USE_BCRYPT */
