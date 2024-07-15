#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "crypto_wrapper.h"

#ifdef OPENSSL
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

#ifdef WIN
#pragma comment (lib, "libcrypto.lib")
#pragma comment (lib, "openssl.lib")
#endif // #ifdef WIN

static constexpr size_t HASH_SIZE_BYTES = 32;  // SHA-256 hash size
static constexpr size_t IV_SIZE_BYTES = 12;    // Standard GCM IV size
static constexpr size_t GMAC_SIZE_BYTES = 16;  // Standard GCM tag size




bool CryptoWrapper::hmac_SHA256(IN const BYTE* key, size_t keySizeBytes, IN const BYTE* message, IN size_t messageSizeBytes, OUT BYTE* macBuffer, IN size_t macBufferSizeBytes)
{
    unsigned int len = HASH_SIZE_BYTES;

    if (macBufferSizeBytes < HASH_SIZE_BYTES)
    {
        return false;
    }

    HMAC_CTX* ctx = HMAC_CTX_new();
    if (ctx == NULL)
    {
        return false;
    }

    if (HMAC_Init_ex(ctx, key, keySizeBytes, EVP_sha256(), NULL) != 1)
    {
        HMAC_CTX_free(ctx);
        return false;
    }

    if (HMAC_Update(ctx, message, messageSizeBytes) != 1)
    {
        HMAC_CTX_free(ctx);
        return false;
    }

    if (HMAC_Final(ctx, macBuffer, &len) != 1)
    {
        HMAC_CTX_free(ctx);
        return false;
    }

    HMAC_CTX_free(ctx);
    return true;
}



bool CryptoWrapper::deriveKey_HKDF_SHA256(IN const BYTE* salt, IN size_t saltSizeBytes,
    IN const BYTE* secretMaterial, IN size_t secretMaterialSizeBytes,
    IN const BYTE* context, IN size_t contextSizeBytes,
    OUT BYTE* outputBuffer, IN size_t outputBufferSizeBytes)
{
    bool ret = false;
    EVP_PKEY_CTX* pctx = NULL;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL)
    {
        printf("failed to get HKDF context\n");
        goto err;    
    }

    if (EVP_PKEY_derive_init(pctx) <= 0)
    {
        printf("EVP_PKEY_derive_init failed\n");
        goto err;
    }

    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) <= 0)
    {
        printf("EVP_PKEY_CTX_hkdf_mode failed\n");
        goto err;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0)
    {
        printf("EVP_PKEY_CTX_set_hkdf_md failed\n");
        goto err;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltSizeBytes) <= 0)
    {
        printf("EVP_PKEY_CTX_set1_hkdf_salt failed\n");
        goto err;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secretMaterial, secretMaterialSizeBytes) <= 0)
    {
        printf("EVP_PKEY_CTX_set1_hkdf_key failed\n");
        goto err;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, context, contextSizeBytes) <= 0)
    {
        printf("EVP_PKEY_CTX_add1_hkdf_info failed\n");
        goto err;
    }

    if (EVP_PKEY_derive(pctx, outputBuffer, &outputBufferSizeBytes) <= 0)
    {
        printf("EVP_PKEY_derive failed\n");
        goto err;
    }

    ret = true;

err:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}



size_t CryptoWrapper::getCiphertextSizeAES_GCM256(IN size_t plaintextSizeBytes)
{
	return plaintextSizeBytes + IV_SIZE_BYTES + GMAC_SIZE_BYTES;
}


size_t CryptoWrapper::getPlaintextSizeAES_GCM256(IN size_t ciphertextSizeBytes)
{
	return (ciphertextSizeBytes > IV_SIZE_BYTES + GMAC_SIZE_BYTES ? ciphertextSizeBytes - IV_SIZE_BYTES - GMAC_SIZE_BYTES : 0);
}

bool CryptoWrapper::encryptAES_GCM256(IN const BYTE* key, IN size_t keySizeBytes,
    IN const BYTE* plaintext, IN size_t plaintextSizeBytes,
    IN const BYTE* aad, IN size_t aadSizeBytes,
    OUT BYTE* ciphertextBuffer, IN size_t ciphertextBufferSizeBytes, OUT size_t* pCiphertextSizeBytes)
{
    if (plaintext == NULL || key == NULL || ciphertextBuffer == NULL || pCiphertextSizeBytes == NULL)
    {
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        return false;
    }

    BYTE iv[IV_SIZE_BYTES];
    if (RAND_bytes(iv, IV_SIZE_BYTES) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int len;
    int ciphertext_len;
    if (aad != NULL && aadSizeBytes > 0)
    {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aadSizeBytes) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    if (EVP_EncryptUpdate(ctx, ciphertextBuffer + IV_SIZE_BYTES, &len, plaintext, plaintextSizeBytes) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertextBuffer + IV_SIZE_BYTES + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GMAC_SIZE_BYTES, ciphertextBuffer + IV_SIZE_BYTES + ciphertext_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    memcpy(ciphertextBuffer, iv, IV_SIZE_BYTES);
    *pCiphertextSizeBytes = IV_SIZE_BYTES + ciphertext_len + GMAC_SIZE_BYTES;

    EVP_CIPHER_CTX_free(ctx);
    return true;
}
bool CryptoWrapper::decryptAES_GCM256(IN const BYTE* key, IN size_t keySizeBytes,
    IN const BYTE* ciphertext, IN size_t ciphertextSizeBytes,
    IN const BYTE* aad, IN size_t aadSizeBytes,
    OUT BYTE* plaintextBuffer, IN size_t plaintextBufferSizeBytes, OUT size_t* pPlaintextSizeBytes)
{
    if (ciphertext == NULL || key == NULL || plaintextBuffer == NULL || pPlaintextSizeBytes == NULL)
    {
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        return false;
    }

    const BYTE* iv = ciphertext;
    const BYTE* tag = ciphertext + ciphertextSizeBytes - GMAC_SIZE_BYTES;
    const BYTE* encryptedData = ciphertext + IV_SIZE_BYTES;
    size_t encryptedDataSize = ciphertextSizeBytes - IV_SIZE_BYTES - GMAC_SIZE_BYTES;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int len;
    int plaintext_len;
    if (aad != NULL && aadSizeBytes > 0)
    {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aadSizeBytes) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    if (EVP_DecryptUpdate(ctx, plaintextBuffer, &len, encryptedData, encryptedDataSize) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GMAC_SIZE_BYTES, (void*)tag) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintextBuffer + len, &len) <= 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len += len;

    *pPlaintextSizeBytes = plaintext_len;

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool CryptoWrapper::readRSAKeyFromFile(IN const char* keyFilename, IN const char* filePassword, OUT KeypairContext** pKeyContext)
{
    FILE* fp = fopen(keyFilename, "r");
    if (!fp)
    {
        return false;
    }

    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, NULL, NULL, (void*)filePassword);
    fclose(fp);

    if (!pkey)
    {
        return false;
    }

    *pKeyContext = pkey;
    return true;
}



bool CryptoWrapper::signMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN KeypairContext* privateKeyContext, OUT BYTE* signatureBuffer, IN size_t signatureBufferSizeBytes)
{
    if (message == NULL || privateKeyContext == NULL || signatureBuffer == NULL)
    {
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
    {
        return false;
    }

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, privateKeyContext) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    if (EVP_DigestSignUpdate(ctx, message, messageSizeBytes) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    size_t sigLen = signatureBufferSizeBytes;
    if (EVP_DigestSignFinal(ctx, signatureBuffer, &sigLen) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    EVP_MD_CTX_free(ctx);
    return true;
}

bool CryptoWrapper::verifyMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN KeypairContext* publicKeyContext, IN const BYTE* signature, IN size_t signatureSizeBytes, OUT bool* result)
{
    if (message == NULL || publicKeyContext == NULL || signature == NULL || result == NULL)
    {
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
    {
        return false;
    }

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, publicKeyContext) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    if (EVP_DigestVerifyUpdate(ctx, message, messageSizeBytes) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    int verify = EVP_DigestVerifyFinal(ctx, signature, signatureSizeBytes);
    *result = (verify == 1);

    EVP_MD_CTX_free(ctx);
    return (verify == 1);
}



void CryptoWrapper::cleanKeyContext(INOUT KeypairContext** pKeyContext)
{
	if (*pKeyContext != NULL)
	{
		EVP_PKEY_CTX_free(*pKeyContext);
		*pKeyContext = NULL;
	}
}


bool CryptoWrapper::writePublicKeyToPemBuffer(IN KeypairContext* keyContext, OUT BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{
	return false;
}


bool CryptoWrapper::loadPublicKeyFromPemBuffer(INOUT KeypairContext* context, IN const BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{
	return false;
}

bool CreatePeerPublicKey(const BYTE* peerPublicKey, size_t peerPublicKeySizeBytes, EVP_PKEY** genPeerPublicKey)
{
    if (peerPublicKey == NULL || genPeerPublicKey == NULL)
    {
        return false;
    }

    BIO* bio = BIO_new_mem_buf(peerPublicKey, peerPublicKeySizeBytes);
    if (bio == NULL)
    {
        return false;
    }

    EVP_PKEY* pkey = d2i_PUBKEY_bio(bio, NULL);
    BIO_free(bio);

    if (pkey == NULL)
    {
        return false;
    }

    *genPeerPublicKey = pkey;
    return true;
}

bool CryptoWrapper::startDh(OUT DhContext** pDhContext, OUT BYTE* publicKeyBuffer, IN size_t publicKeyBufferSizeBytes)
{
    bool ret = false;
    EVP_PKEY_CTX* pctx = NULL;
    EVP_PKEY* dhparams = NULL;
    EVP_PKEY* dhkey = NULL;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (pctx == NULL)
    {
        goto err;
    }

    if (EVP_PKEY_paramgen_init(pctx) <= 0)
    {
        goto err;
    }

    if (EVP_PKEY_CTX_set_dh_nid(pctx, NID_ffdhe3072) <= 0)
    {
        goto err;
    }

    if (EVP_PKEY_paramgen(pctx, &dhparams) <= 0)
    {
        goto err;
    }

    EVP_PKEY_CTX_free(pctx);
    pctx = EVP_PKEY_CTX_new(dhparams, NULL);
    if (pctx == NULL)
    {
        goto err;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0)
    {
        goto err;
    }

    if (EVP_PKEY_keygen(pctx, &dhkey) <= 0)
    {
        goto err;
    }

    if (EVP_PKEY_get_raw_public_key(dhkey, publicKeyBuffer, &publicKeyBufferSizeBytes) <= 0)
    {
        goto err;
    }

    *pDhContext = dhkey;
    ret = true;

err:
    EVP_PKEY_free(dhparams);
    EVP_PKEY_CTX_free(pctx);

    return ret;
}

bool CryptoWrapper::getDhSharedSecret(INOUT DhContext* dhContext, IN const BYTE* peerPublicKey, IN size_t peerPublicKeySizeBytes, OUT BYTE* sharedSecretBuffer, IN size_t sharedSecretBufferSizeBytes)
{
    bool ret = false;
    EVP_PKEY* genPeerPublicKey = NULL;
    EVP_PKEY_CTX* derivationCtx = NULL;

    if (dhContext == NULL || peerPublicKey == NULL || sharedSecretBuffer == NULL)
    {
        goto err;
    }

    if (!CreatePeerPublicKey(peerPublicKey, peerPublicKeySizeBytes, &genPeerPublicKey))
    {
        goto err;
    }

    derivationCtx = EVP_PKEY_CTX_new(dhContext, NULL);
    if (derivationCtx == NULL)
    {
        goto err;
    }

    if (EVP_PKEY_derive_init(derivationCtx) <= 0)
    {
        goto err;
    }

    if (EVP_PKEY_derive_set_peer(derivationCtx, genPeerPublicKey) <= 0)
    {
        goto err;
    }

    size_t secretLen = sharedSecretBufferSizeBytes;
    if (EVP_PKEY_derive(derivationCtx, sharedSecretBuffer, &secretLen) <= 0)
    {
        goto err;
    }

    ret = true;

err:
    EVP_PKEY_free(genPeerPublicKey);
    EVP_PKEY_CTX_free(derivationCtx);
    return ret;
}

void CryptoWrapper::cleanDhContext(INOUT DhContext** pDhContext)
{
	if (*pDhContext != NULL)
	{
		EVP_PKEY_free(*pDhContext);
		*pDhContext = NULL;
	}
}

X509* loadCertificate(const BYTE* certBuffer, size_t certSizeBytes)
{
	int ret = 0;
	BIO* bio = NULL;
	X509* cert = NULL;

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
	{
		printf("BIO_new() fail \n");
		goto err;
	}

	ret = BIO_write(bio, (const void*)certBuffer, (int)certSizeBytes);
	if (ret <= 0)
	{
		printf("BIO_write() fail \n");
		goto err;
	}

	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (cert == NULL)
	{
		printf("PEM_read_bio_X509() fail \n");
		goto err;
	}

err:
	BIO_free(bio);

	return cert;
}

bool CryptoWrapper::checkCertificate(IN const BYTE* cACcertBuffer, IN size_t cACertSizeBytes, IN const BYTE* certBuffer, IN size_t certSizeBytes, IN const char* expectedCN)
{
    bool ret = false;
    X509* userCert = NULL;
    X509* caCert = NULL;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    char certCN[256];

    // Load the CA certificate
    caCert = loadCertificate(cACcertBuffer, cACertSizeBytes);
    if (caCert == NULL)
    {
        printf("loadCertificate() for CA fail \n");
        goto err;
    }

    // Load the user certificate
    userCert = loadCertificate(certBuffer, certSizeBytes);
    if (userCert == NULL)
    {
        printf("loadCertificate() for User fail \n");
        goto err;
    }

    // Set up the store context for the CA certificate
    store = X509_STORE_new();
    if (store == NULL)
    {
        printf("X509_STORE_new() fail \n");
        goto err;
    }

    if (X509_STORE_add_cert(store, caCert) != 1)
    {
        printf("X509_STORE_add_cert() fail \n");
        goto err;
    }

    // Set up the store context for the user certificate
    ctx = X509_STORE_CTX_new();
    if (ctx == NULL)
    {
        printf("X509_STORE_CTX_new() fail \n");
        goto err;
    }

    if (X509_STORE_CTX_init(ctx, store, userCert, NULL) != 1)
    {
        printf("X509_STORE_CTX_init() fail \n");
        goto err;
    }

    // Perform the certificate verification
    if (X509_verify_cert(ctx) != 1)
    {
        printf("X509_verify_cert() fail: %s\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
        goto err;
    }

    // Extract the Common Name (CN) from the user certificate
    X509_NAME* subj = X509_get_subject_name(userCert);
    if (X509_NAME_get_text_by_NID(subj, NID_commonName, certCN, sizeof(certCN)) <= 0)
    {
        printf("X509_NAME_get_text_by_NID() fail \n");
        goto err;
    }

    // Compare the extracted CN with the expected CN
    if (strcmp(certCN, expectedCN) != 0)
    {
        printf("Certificate CN does not match expected CN: %s != %s\n", certCN, expectedCN);
        goto err;
    }

    // If we reach here, all checks have passed
    ret = true;

err:
    if (ctx) X509_STORE_CTX_free(ctx);
    if (store) X509_STORE_free(store);
    if (userCert) X509_free(userCert);
    if (caCert) X509_free(caCert);

    return ret;
}


bool CryptoWrapper::getPublicKeyFromCertificate(IN const BYTE* certBuffer, IN size_t certSizeBytes, OUT KeypairContext** pPublicKeyContext)
{

	return false;
}

#endif // #ifdef OPENSSL

/*
* 
* Usefull links
* -------------------------
* *  
* https://www.intel.com/content/www/us/en/develop/documentation/cpp-compiler-developer-guide-and-reference/top/compiler-reference/intrinsics/intrinsics-for-later-gen-core-proc-instruct-exts/intrinsics-gen-rand-nums-from-16-32-64-bit-ints/rdrand16-step-rdrand32-step-rdrand64-step.html
* https://wiki.openssl.org/index.php/OpenSSL_3.0
* https://www.rfc-editor.org/rfc/rfc3526
* 
* 
* Usefull APIs
* -------------------------
* 
* EVP_MD_CTX_new
* EVP_PKEY_new_raw_private_key
* EVP_DigestSignInit
* EVP_DigestSignUpdate
* EVP_PKEY_CTX_new_id
* EVP_PKEY_derive_init
* EVP_PKEY_CTX_set_hkdf_md
* EVP_PKEY_CTX_set1_hkdf_salt
* EVP_PKEY_CTX_set1_hkdf_key
* EVP_PKEY_derive
* EVP_CIPHER_CTX_new
* EVP_EncryptInit_ex
* EVP_EncryptUpdate
* EVP_EncryptFinal_ex
* EVP_CIPHER_CTX_ctrl
* EVP_DecryptInit_ex
* EVP_DecryptUpdate
* EVP_DecryptFinal_ex
* OSSL_PARAM_BLD_new
* OSSL_PARAM_BLD_push_BN
* EVP_PKEY_CTX_new_from_name
* EVP_PKEY_fromdata_init
* EVP_PKEY_fromdata
* EVP_PKEY_CTX_new
* EVP_PKEY_derive_init
* EVP_PKEY_derive_set_peer
* EVP_PKEY_derive_init
* BIO_new
* BIO_write
* PEM_read_bio_X509
* X509_STORE_new
* X509_STORE_CTX_new
* X509_STORE_add_cert
* X509_verify_cert
* X509_check_host
*
*
*
*/
