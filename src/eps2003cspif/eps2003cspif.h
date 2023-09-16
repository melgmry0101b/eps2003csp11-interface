/*-----------------------------------------------------------------*\
 *
 * eps2003cspif.h
 *   eps2003cspif
 *     eps2003csp11-interface
 *
 * MIT - see LICENSE at root directory
 *
 * CREATED: 2022-11-24 06:07 PM
 * AUTHORS: Mohammed Elghamry <elghamry.connect[at]outlook[dot]com>
 *
\*-----------------------------------------------------------------*/

#ifndef EPS2003CSPIF_H
#define EPS2003CSPIF_H

#include "errcodes.h"

// ====================
// ====== Macros ======
// ====================

#define STRINGIZE(x) #x
#define STRINGIZE_EXPRESSION(x) STRINGIZE(x)

#ifdef EPS2003CSPIF_EXPORTS
#ifdef __cplusplus
#define DllExport extern "C" __declspec(dllexport)
#else
#define DllExport __declspec(dllexport)
#endif // __cpluscplus
#else
#ifdef __cplusplus
#define DllExport extern "C" __declspec(dllimport)
#else
#define DllExport __declspec(dllimport)
#endif // __cpluscplus
#endif // EPS2003CSPIF_EXPORTS

#define DLLENTRY(return_type) DllExport return_type APIENTRY

// ==============================
// ====== Exported Methods ======
// ==============================

// ------------------------------------------------------
// This function is used as an interface for other
//  language to free memory allocated by the library.
// ------------------------------------------------------
DLLENTRY(void) FreeMem(void *p);

// ------------------------------------------------------
// Open the library for the first slot with a token.
// ------------------------------------------------------
DLLENTRY(HRESULT) OpenKiLibrary(BSTR pwszLibName, BSTR pwszPin);

// ------------------------------------------------------
// Close the library.
// ------------------------------------------------------
DLLENTRY(HRESULT) CloseKiLibrary();

// ------------------------------------------------------
// Sign with CAdES-BES using the provided root cert.
// ------------------------------------------------------
DLLENTRY(HRESULT) SignWithCadesBes(BSTR pwszRootCert, BSTR pwszData, BSTR *ppwszSignature);

// ------------------------------------------------------
// Create SHA256 Hash.
// 
// Free buffer returned in `ppbHash` using FreeMem
//  from this library.
// ------------------------------------------------------
DLLENTRY(HRESULT) SHA256(BYTE *pbData, DWORD cbData, BYTE **ppbHash, DWORD *pcbHash);

// ------------------------------------------------------
// Create SHA256 Hash and set the output as BSTR.
// ------------------------------------------------------
DLLENTRY(HRESULT) SHA256_STR(BYTE *pbData, DWORD cbData, BSTR *ppwszHash);

// ------------------------------------------------------
// Create base64 string and set the output as BSTR.
// ------------------------------------------------------
DLLENTRY(HRESULT) BASE64(BYTE *pbData, DWORD cbData, BSTR *ppwszBase64);

#endif //EPS2003CSPIF_H
