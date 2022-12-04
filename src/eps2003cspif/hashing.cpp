/*-----------------------------------------------------------------*\
 *
 * hashing.cpp
 *   eps2003cspif
 *     eps2003csp11-interface
 *
 * MIT - see LICENSE at root directory
 *
 * CREATED: 2022-12-3 03:42 PM
 * AUTHORS: Mohammed Elghamry <elghamry.connect[at]outlook[dot]com>
 *
\*-----------------------------------------------------------------*/

#include "pch.h"

#include "eps2003cspif.h"

#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS      ((NTSTATUS)0x00000000)

#define SHA256_SIZE         32 // 32 Bytes, 256 bits

// ==============================
// ====== Exported Methods ======
// ==============================

// ------------------------------------------------------
// 
// Create SHA256 Hash.
// 
// Free buffer returned in `ppbHash` using FreeMem
//  from this library.
// 
// ------------------------------------------------------
DLLENTRY(HRESULT) SHA256(BYTE *pbData, DWORD cbData, BYTE **ppbHash, DWORD *pcbHash)
{
    if (!ppbHash) { return E_POINTER; }
    if (!pcbHash) { return E_POINTER; }

    HRESULT hr{ S_OK };
    NTSTATUS status{ STATUS_SUCCESS };

    BCRYPT_ALG_HANDLE   hAlg{ nullptr };
    BCRYPT_HASH_HANDLE  hHash{ nullptr };

    BYTE    *pbHash{ nullptr };

    // === Reserve memory for hash
    pbHash = new(std::nothrow) BYTE[SHA256_SIZE];
    if (!pbHash)
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }

    // === Open algorithm handle
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(status))
    {
        _RPT1(_CRT_WARN, "BCryptOpenAlgorithmProvider failed with NTSTATUS 0x%x", status);
        hr = HRESULT_FROM_NT(status);
        goto done;
    }

    // === Create hasher
    status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    if (!NT_SUCCESS(status))
    {
        _RPT1(_CRT_WARN, "BCryptCreateHash failed with NTSTATUS 0x%x", status);
        hr = HRESULT_FROM_NT(status);
        goto done;
    }

    // === Hash data
    status = BCryptHashData(hHash, pbData, cbData, 0);
    if (!NT_SUCCESS(status))
    {
        _RPT1(_CRT_WARN, "BCryptHashData failed with NTSATUS 0x%x", status);
        hr = HRESULT_FROM_NT(status);
        goto done;
    }

    // === Get the hashed data and close the hash
    status = BCryptFinishHash(hHash, pbHash, SHA256_SIZE, 0);
    if (!NT_SUCCESS(status))
    {
        _RPT1(_CRT_WARN, "BCryptFinishHash failed with NTSATUS 0x%x", status);
        hr = HRESULT_FROM_NT(status);
        goto done;
    }

    // === Set the output
    (*ppbHash) = pbHash;
    (*pcbHash) = SHA256_SIZE;

done:
    if (hAlg)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    if (hHash)
    {
        BCryptDestroyHash(hHash);
    }

    if (FAILED(hr) && pbHash)
    {
        delete[] pbHash;
    }

    return hr;
}

// ------------------------------------------------------
// 
// Create SHA256 Hash and set the output as BSTR.
// 
// ------------------------------------------------------
DLLENTRY(HRESULT) SHA256_STR(BYTE *pbData, DWORD cbData, BSTR *ppwszHash)
{
    if (!ppwszHash) { return E_POINTER; }

    HRESULT hr{ S_OK };

    BYTE    *pbHash{ nullptr };
    DWORD   cbHash{ 0 };

    LPWSTR  pwszHashRawHex{ nullptr };
    DWORD   cchHashRawHex{ 0 };

    BSTR    pwszHash{ nullptr };

    // === Allocate the memory for the hex
    // Length of sha256 hex is 64 characters + 1 null character
    pwszHashRawHex = new(std::nothrow) WCHAR[(SHA256_SIZE * 2) + 1];
    cchHashRawHex = (SHA256_SIZE * 2) + 1;
    if (!pwszHashRawHex)
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }

    // === Hash the passed data
    hr = SHA256(pbData, cbData, &pbHash, &cbHash);
    if (FAILED(hr)) { goto done; }

    // === Convert the hash to hex string
    // NOTE: cchHashRawHex will now contain the length of pwszHashRawHex without the null character.
    if (!CryptBinaryToString(pbHash, cbHash, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, pwszHashRawHex, &cchHashRawHex))
    {
        _RPT0(_CRT_WARN, "CryptBinaryToString failed.");
        hr = E_UNEXPECTED;
        goto done;
    }

    // === Allocate BSTR
    pwszHash = SysAllocString(pwszHashRawHex);
    if (!pwszHash)
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }

    (*ppwszHash) = pwszHash;

done:
    if (pbHash)
    {
        delete[] pbHash;
    }

    if (pwszHashRawHex)
    {
        delete[] pwszHashRawHex;
    }

    return hr;
}

// ------------------------------------------------------
// 
// Create base64 string and set the output as BSTR.
// 
// ------------------------------------------------------
DLLENTRY(HRESULT) BASE64(BYTE *pbData, DWORD cbData, BSTR *ppwszBase64)
{
    if (!ppwszBase64) { return E_POINTER; }

    HRESULT hr{ S_OK };

    LPWSTR pwszBase64Output{ nullptr };
    DWORD  cchBase64Output{ 0 };

    BSTR pwszBase64{ nullptr };

    // === Calculate the output size
    if (!CryptBinaryToString(pbData, cbData, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &cchBase64Output))
    {
        _RPT0(_CRT_WARN, "CryptBinaryToString failed to calculate memory.");
        hr = E_UNEXPECTED;
        goto done;
    }

    // === Allocate memory for the output
    pwszBase64Output = new(std::nothrow) WCHAR[cchBase64Output];
    if (!pwszBase64Output)
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }

    // === Convert to base64
    // NOTE: cchBase64Output will now contain the length of pwszHashRawHex without the null character.
    if (!CryptBinaryToString(pbData, cbData, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, pwszBase64Output, &cchBase64Output))
    {
        _RPT0(_CRT_WARN, "CryptBinaryToString failed.");
        hr = E_UNEXPECTED;
        goto done;
    }

    // === Allocate BSTR
    pwszBase64 = SysAllocString(pwszBase64Output);
    if (!pwszBase64)
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }

    (*ppwszBase64) = pwszBase64;

done:
    if (pwszBase64Output)
    {
        delete[] pwszBase64Output;
    }

    return hr;
}
