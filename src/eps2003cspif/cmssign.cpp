/*-----------------------------------------------------------------*\
 *
 * cmssign.cpp
 *   eps2003cspif
 *     eps2003csp11-interface
 *
 * MIT - see LICENSE at root directory
 *
 * CREATED: 2022-12-3 12:24 PM
 * AUTHORS: Mohammed Elghamry <elghamry.connect[at]outlook[dot]com>
 *
\*-----------------------------------------------------------------*/

#include "pch.h"

#include "eps2003cspif.h"
#include "cmssign.h"

// REF: https://www.codeproject.com/Articles/1256991/The-AdES-Collection-CAdES-XAdES-PAdES-and-ASiC

// ==========================
// ====== Declarations ======
// ==========================

// ============================
// ====== Public Methods ======
// ============================

// ------------------------------------------------------
// 
// Create CAdES-BES message for content with one signer.
// 
// ------------------------------------------------------
HRESULT CreateCadesBesSignedMessage(BYTE *pbContent, DWORD cbContent, PCCERT_CONTEXT pCert, BYTE **ppbEncodedBlob, DWORD *pcbEncodedBlob)
{
    HRESULT hr{ S_OK };

    asn_enc_rval_t asnEncodingResult{};

    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hPrivateKey{ 0 };
    DWORD                           dwPrivateKeySpec{ 0 };
    BOOL                            bShouldCallerFreePrivateKeyHandle{ FALSE };

    FILETIME        signingTime{ 0 };
    BYTE            *pbEncodedSigningTime{ nullptr };
    DWORD           cbEncodedSigningTime{ 0 };
    CRYPT_ATTR_BLOB attrBlobSigningTime{ 0 };

    BYTE    *pbCertHash{ nullptr };
    DWORD   cbCertHash{ 0 };

    ESSCertIDv2             essCert{};
    ESSCertIDv2             *essCerts[]{ &essCert };
    SigningCertificateV2    signingCert{};
    std::vector<BYTE>       vecEncodedSigningCert{};
    CRYPT_ATTR_BLOB         attrBlobSigningCert{};

    // Holding attributes for the message
    CRYPT_ATTRIBUTE messageAttributes[2]{};

    // Encoded OID of sha256. "2.16.840.1.101.3.4.2.1"
    BYTE                    oid_sha256_bytes[]{ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
    OBJECT_IDENTIFIER_t     oid_sha256{};
    AlgorithmIdentifier     algid_sha256{};
    oid_sha256.buf = oid_sha256_bytes;
    oid_sha256.size = sizeof(oid_sha256_bytes);
    algid_sha256.algorithm = oid_sha256;

    // Holding information about the certificate
    CERT_BLOB certsEncoded[1]{};
    certsEncoded[0].cbData = pCert->cbCertEncoded;
    certsEncoded[0].pbData = pCert->pbCertEncoded;

    // Holding the information about signers -which is one in our case-
    CMSG_SIGNER_ENCODE_INFO msgSigners[1]{};

    // Holding the information about message signing CMSG_SIGNED
    CMSG_SIGNED_ENCODE_INFO msgInfo{};

    // Here is where we store our encoded message
    BYTE    *pbEncodedBlob{ nullptr };
    DWORD   cbEncodedBlob{ 0 };

    // Handle for the opened message
    HCRYPTMSG hMsg{ nullptr };

    // ======
    // ====== Get Certificate Private Key
    // ======

    if (!CryptAcquireCertificatePrivateKey(
        pCert,
        0,
        nullptr,
        &hPrivateKey,
        &dwPrivateKeySpec,
        &bShouldCallerFreePrivateKeyHandle))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        _RPT1(_CRT_WARN, "CryptAcquireCertificatePrivateKey() failed with HRESULT 0x%x\n", hr);
        goto done;
    }

    // ======
    // ====== Create PKCS#9 Signing Time Attribute
    // ======

    GetSystemTimeAsFileTime(&signingTime);

    if (!CryptEncodeObjectEx(
        PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
        szOID_RSA_signingTime,
        &signingTime,
        CRYPT_ENCODE_ALLOC_FLAG,
        nullptr,
        &pbEncodedSigningTime,
        &cbEncodedSigningTime))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        _RPT1(_CRT_WARN, "CryptEncodeObjectEx() failed with HRESULT 0x%x\n", hr);
        goto done;
    }

    attrBlobSigningTime.cbData = cbEncodedSigningTime;
    attrBlobSigningTime.pbData = pbEncodedSigningTime;

    messageAttributes[0].pszObjId = const_cast<LPSTR>(szOID_RSA_signingTime);
    messageAttributes[0].cValue = 1;
    messageAttributes[0].rgValue = &attrBlobSigningTime;

    // ======
    // ====== Create SigningCertificateV2
    // ======

    // === Hash the certificate
    hr = SHA256(pCert->pbCertEncoded, pCert->cbCertEncoded, &pbCertHash, &cbCertHash);
    if (FAILED(hr)) { goto done; }

    // === Set the fields on ESSCertIDv2
    essCert.hashAlgorithm = &algid_sha256;
    essCert.certHash.buf = pbCertHash;
    essCert.certHash.size = cbCertHash;

    // === Set the fields on SigningCertificateV2
    signingCert.certs.list.size = 1;
    signingCert.certs.list.count = 1;
    signingCert.certs.list.array = essCerts;

    // === Encode the object
    asnEncodingResult = der_encode(
        &asn_DEF_SigningCertificateV2,
        &signingCert,
        [](const void *buffer, size_t size, void *app_key)
        {
            std::vector<BYTE> *dest = static_cast<std::vector<BYTE> *>(app_key);
            auto currentVectorSize = dest->size();
            dest->resize(currentVectorSize + size);
            std::memcpy(dest->data() + currentVectorSize, buffer, size);
            return 0;
        },
        &vecEncodedSigningCert);
    if (asnEncodingResult.encoded == -1)
    {
        // Error occurred during encoding
        hr = EPSIF_E_ENCODING_FAILED;
        _RPT0(_CRT_WARN, "der_encode() failed.\n");
        goto done;
    }

    // === Set the attribute
    attrBlobSigningCert.cbData = static_cast<DWORD>(vecEncodedSigningCert.size());
    attrBlobSigningCert.pbData = vecEncodedSigningCert.data();

    messageAttributes[1].pszObjId = const_cast<LPSTR>("1.2.840.113549.1.9.16.2.47"); // PKCS#9, S/MIME, SigningCertificateV2
    messageAttributes[1].cValue = 1;
    messageAttributes[1].rgValue = &attrBlobSigningCert;

    // ======
    // ====== Prepare signer info
    // ======

    msgSigners[0].cbSize                    = sizeof(CMSG_SIGNER_ENCODE_INFO);
    msgSigners[0].pCertInfo                 = pCert->pCertInfo;
    msgSigners[0].hCryptProv                = hPrivateKey;
    msgSigners[0].dwKeySpec                 = dwPrivateKeySpec;
    msgSigners[0].HashAlgorithm.pszObjId    = const_cast<LPSTR>(szOID_NIST_sha256);
    msgSigners[0].cAuthAttr                 = 2;
    msgSigners[0].rgAuthAttr                = messageAttributes;

    // ======
    // ====== Prepare message info
    // ======

    msgInfo.cbSize          = sizeof(CMSG_SIGNED_ENCODE_INFO);
    msgInfo.cSigners        = 1;
    msgInfo.rgSigners       = msgSigners;
    msgInfo.cCertEncoded    = 1;
    msgInfo.rgCertEncoded   = certsEncoded;

    // ======
    // ====== Calculate message size
    // ======

    cbEncodedBlob = CryptMsgCalculateEncodedLength(
        PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
        CMSG_DETACHED_FLAG | CMSG_CMS_ENCAPSULATED_CONTENT_FLAG,
        CMSG_SIGNED,
        &msgInfo,
        const_cast<LPSTR>(szOID_RSA_digestedData),
        cbContent);
    if (!cbEncodedBlob)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        _RPT1(_CRT_WARN, "CryptMsgCalculateEncodedLength() failed with HRESULT 0x%x\n", hr);
        goto done;
    }

    // ======
    // ====== Allocate memory for encoded message
    // ======

    pbEncodedBlob = new(std::nothrow) BYTE[cbEncodedBlob];
    if (!pbEncodedBlob)
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }

    // ======
    // ====== Open the message for encoding
    // ======

    hMsg = CryptMsgOpenToEncode(
        PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
        CMSG_DETACHED_FLAG | CMSG_CMS_ENCAPSULATED_CONTENT_FLAG,
        CMSG_SIGNED,
        &msgInfo,
        const_cast<LPSTR>(szOID_RSA_digestedData),
        nullptr);
    if (!hMsg)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        _RPT1(_CRT_WARN, "CryptMsgOpenToEncode() failed with HRESULT 0x%x\n", hr);
        goto done;
    }

    // ======
    // ====== Update the message with our content
    // ======

    if (!CryptMsgUpdate(hMsg, pbContent, cbContent, TRUE))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        _RPT1(_CRT_WARN, "CryptMsgUpdate() failed with HRESULT 0x%x\n", hr);
        goto done;
    }

    // ======
    // ====== Get the encoded message
    // ======

    if (!CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, pbEncodedBlob, &cbEncodedBlob))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        _RPT1(_CRT_WARN, "CryptMsgGetParam() failed with HRESULT 0x%x\n", hr);
        goto done;
    }

    // ======
    // ====== Finally, return the data to the caller
    // ======

    (*ppbEncodedBlob) = pbEncodedBlob;
    (*pcbEncodedBlob) = cbEncodedBlob;

done:
    if (bShouldCallerFreePrivateKeyHandle)
    {
        if (dwPrivateKeySpec == CERT_NCRYPT_KEY_SPEC)
        {
            NCryptFreeObject(hPrivateKey);
        }
        else
        {
            CryptReleaseContext(hPrivateKey, 0);
        }
    }

    if (pbEncodedSigningTime)
    {
        LocalFree(pbEncodedSigningTime);
    }

    if (pbCertHash)
    {
        delete[] pbCertHash;
    }

    if (hMsg)
    {
        CryptMsgClose(hMsg);
    }

    return hr;
}
