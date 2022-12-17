/*-----------------------------------------------------------------*\
 *
 * eps2003cspif.cpp
 *   eps2003cspif
 *     eps2003csp11-interface
 *
 * MIT - see LICENSE at root directory
 *
 * CREATED: 2022-11-24 06:12 PM
 * AUTHORS: Mohammed Elghamry <elghamry.connect[at]outlook[dot]com>
 *
\*-----------------------------------------------------------------*/

#include "pch.h"

#include "eps2003cspif.h"
#include "cmssign.h"

#define MAX_BUFFER 255

// =====================
// ====== Globals ======
// =====================

static bool g_IsInitialized{ false };
static CK_SESSION_HANDLE g_hSession{ 0 };

// ==========================
// ====== Declarations ======
// ==========================

HRESULT Initialize();
HRESULT Finalize();
HRESULT GetFirstSlotId(CK_SLOT_ID &firstSlotId);
HRESULT OpenSessionForSlot(CK_SLOT_ID slotId, CK_SESSION_HANDLE &hOpenedSession);
HRESULT SessionLogin(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pPin, CK_ULONG ulPinLen);
HRESULT CheckAnyCertificateExistsInSlot(CK_SESSION_HANDLE hSession);
HRESULT GetCertificateFromMyStore(BSTR pwszCertificateName, PCCERT_CONTEXT &pCertificate);

// ==============================
// ====== Exported Methods ======
// ==============================

// ------------------------------------------------------
// 
// This function is used as an interface for other
//  language to free memory allocated by the library.
// 
// ------------------------------------------------------
DLLENTRY(void) FreeMem(void *p)
{
    // All our allocations in the library is of arrays of
    //  simple types using new[], so we free using delete[].
    delete[] p;
}

// ------------------------------------------------------
// 
// Open the library for the first slot with a token.
// 
// ------------------------------------------------------
DLLENTRY(HRESULT) OpenKiLibrary(BSTR pwszPin)
{
    if (g_IsInitialized) { return S_OK; }

    HRESULT hr{ S_OK };

    CK_SLOT_ID ulFirstSlotId{ 0 };

    size_t pinLen{ 0 };
    char mbPin[MAX_BUFFER]{ '\0' };

    // create a locale to accept utf8 pins
    _locale_t utf8_locale = _create_locale(LC_ALL, ".utf8");

    // === Convert Passed Strings ===
    if (_wcstombs_s_l(&pinLen, mbPin, MAX_BUFFER, pwszPin, MAX_BUFFER - 1, utf8_locale) != ERROR_SUCCESS)
    {
        _free_locale(utf8_locale);
        return E_UNEXPECTED;
    }

    _free_locale(utf8_locale);

    // === Initialize Library ===
    hr = Initialize();
    if (FAILED(hr)) { goto error; }

    // === Get First Slot ID ===
    hr = GetFirstSlotId(ulFirstSlotId);
    if (FAILED(hr)) { goto error;}

    // === Open Session on Selected Slot ===
    hr = OpenSessionForSlot(ulFirstSlotId, g_hSession);
    if (FAILED(hr)) { goto error; }

    // === Login into session ===
    hr = SessionLogin(g_hSession, reinterpret_cast<CK_CHAR_PTR>(mbPin), static_cast<CK_ULONG>(pinLen));
    if (FAILED(hr)) { goto error; }

    // === Check if a certificate is present in the token ===
    hr = CheckAnyCertificateExistsInSlot(g_hSession);
    if (FAILED(hr)) { goto error; }

    // Open Library Succeeded
    return S_OK;

error:
    if (g_IsInitialized) { Finalize(); }

    return hr;
}

// ------------------------------------------------------
// 
// Close the library.
// 
// ------------------------------------------------------
DLLENTRY(HRESULT) CloseKiLibrary()
{
    if (!g_IsInitialized) { return S_OK; }

    return Finalize();
}

// ------------------------------------------------------
// 
// Sign with CAdES-BES using the provided root cert.
// 
// ------------------------------------------------------
DLLENTRY(HRESULT) SignWithCadesBes(BSTR pwszRootCert, BSTR pwszData, BSTR *ppwszSignature)
{
    // NOTE: Here a decision has been made to detach this method from
    //  being tied to the CryptoKi library, as it can be used without
    //  the ePass2003 PKI token.
    // if (!g_IsInitialized) { return EPSIF_E_NOT_INITIALIZED; }

    HRESULT hr{ S_OK };

    char    *mbData{ nullptr };
    size_t  cchData{ 0 };

    PCCERT_CONTEXT pRootCert{ nullptr };

    BYTE    *pbEncodedMessage{ nullptr };
    DWORD   cbEncodedMessage{ 0 };

    BSTR pwszSignature{ nullptr };

    _locale_t utf8_locale = _create_locale(LC_ALL, ".utf8");

    // === Prepare data to be bytes ===
    // Get required size
    if (_wcstombs_s_l(&cchData, nullptr, 0, pwszData, 0, utf8_locale) != ERROR_SUCCESS)
    {
        hr = E_UNEXPECTED;
        goto done;
    }

    // Allocate buffer and convert
    mbData = new(std::nothrow) char[cchData + 1]; // Add 1 for appended null
    if (!mbData)
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }

    if (_wcstombs_s_l(&cchData, mbData, cchData + 1, pwszData, cchData, utf8_locale) != ERROR_SUCCESS)
    {
        hr = E_UNEXPECTED;
        goto done;
    }

    // === Get the root certificate from the store ===
    hr = GetCertificateFromMyStore(pwszRootCert, pRootCert);
    if (FAILED(hr)) { goto done; }

    // === Create the encoded CAdES-BES message
    hr = CreateCadesBesSignedMessage(
        reinterpret_cast<BYTE *>(mbData),
        static_cast<DWORD>(cchData - 1), // Omitting the null terminator
        pRootCert,
        &pbEncodedMessage,
        &cbEncodedMessage);
    if (FAILED(hr)) { goto done; }

    // === Create Bas64
    hr = BASE64(pbEncodedMessage, cbEncodedMessage, &pwszSignature);
    if (FAILED(hr)) { goto done; }

    // === Set output
    (*ppwszSignature) = pwszSignature;

done:
    _free_locale(utf8_locale);

    if (mbData)
    {
        delete[] mbData;
    }

    if (pRootCert)
    {
        CertFreeCertificateContext(pRootCert);
    }

    if (pbEncodedMessage)
    {
        delete[] pbEncodedMessage;
    }

    return hr;
}

// =============================
// ====== Private Methods ======
// =============================

// ------------------------------------------------------
// 
// Initialize the library for operations.
// 
// ------------------------------------------------------
HRESULT Initialize()
{
    assert(g_IsInitialized == false);

    CK_RV result{ CKR_OK };

    // Send initialization command to the library
    result = C_Initialize(nullptr);
    if (result != CKR_OK && result != CKR_CRYPTOKI_ALREADY_INITIALIZED)
    {
        _RPT1(_CRT_WARN, "Error occurred during initialization. Code 0x%x\n", result);
        return EPSIF_E_INIT_FAILED;
    }

    g_IsInitialized = true;

    return S_OK;
}

// ------------------------------------------------------
//
// Close the library.
// 
// ------------------------------------------------------
HRESULT Finalize()
{
    assert(g_IsInitialized == true);

    CK_RV result{ CKR_OK };

    // Close session ignoring any errors
    C_CloseSession(g_hSession);

    // Send finalization command to the library
    result = C_Finalize(nullptr);
    if (result != CKR_OK && result != CKR_CRYPTOKI_NOT_INITIALIZED)
    {
        _RPT1(_CRT_WARN, "Error occurred during finalization. Code 0x%x\n", result);
        return EPSIF_E_FINALIZE_FAILED;
    }

    g_IsInitialized = false;

    return S_OK;
}

// ------------------------------------------------------
//
// Get the ID of the first slot that has a token present.
// 
// ------------------------------------------------------
HRESULT GetFirstSlotId(CK_SLOT_ID &firstSlotId)
{
    assert(g_IsInitialized == true);

    CK_RV result{ CKR_OK };

    CK_ULONG ulSlotsCount{ 0 };
    std::unique_ptr<CK_SLOT_ID> slotList{ nullptr };

    result = C_GetSlotList(true, nullptr, &ulSlotsCount);
    if (result != CKR_OK)
    {
        _RPT1(_CRT_WARN, "Error occurred during obtaining slots count. Code 0x%x\n", result);
        return EPSIF_E_CANNOT_GET_SLOTS;
    }

    if (ulSlotsCount == 0)
    {
        _RPT0(_CRT_WARN, "No slots found.\n");
        return EPSIF_E_NO_SLOTS_FOUND;
    }

    slotList = std::make_unique<CK_SLOT_ID>(ulSlotsCount);
    result = C_GetSlotList(true, slotList.get(), &ulSlotsCount);
    if (result != CKR_OK)
    {
        _RPT1(_CRT_WARN, "Error occurred during obtaining slots. Code 0x%x\n", result);
        return EPSIF_E_CANNOT_GET_SLOTS;
    }

    firstSlotId = slotList.get()[0];

    return S_OK;
}

// ------------------------------------------------------
//
// Open session on a slot.
// 
// ------------------------------------------------------
HRESULT OpenSessionForSlot(CK_SLOT_ID slotId, CK_SESSION_HANDLE &hOpenedSession)
{
    assert(g_IsInitialized == true);

    CK_RV result{ CKR_OK };
    CK_SESSION_HANDLE hSession{ 0 };
    
    // NOTE: CKF_SERIAL_SESSION has always to be set for legacy reasons.
    result = C_OpenSession(slotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession);
    if (result != CKR_OK)
    {
        _RPT1(_CRT_WARN, "Error occurred during opening session. Code 0x%x\n", result);
        return EPSIF_E_OPEN_SESSION_FAILED;
    }

    hOpenedSession = hSession;

    return S_OK;
}

// ------------------------------------------------------
//
// Login into session.
// 
// ------------------------------------------------------
HRESULT SessionLogin(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    assert(g_IsInitialized == true);

    CK_RV result{ CKR_OK };

    result = C_Login(hSession, CKU_USER, pPin, ulPinLen);
    if (result != CKR_OK)
    {
        _RPT1(_CRT_WARN, "Error occurred during login. Code 0x%x\n", result);
        return EPSIF_E_LOGIN_FAILED;
    }

    return S_OK;
}

// ------------------------------------------------------
//
// Check if any certificate exists in slot.
// 
// ------------------------------------------------------
HRESULT CheckAnyCertificateExistsInSlot(CK_SESSION_HANDLE hSession)
{
    assert(g_IsInitialized == true);

    CK_RV result{ CKR_OK };

    CK_OBJECT_HANDLE obj{ 0 };
    CK_ULONG ulObjCount{ 0 };

    CK_OBJECT_CLASS     objClass{ CKO_CERTIFICATE };
    CK_BBOOL            isToken{ CK_TRUE };
    CK_CERTIFICATE_TYPE certType{ CKC_X_509 };

    CK_ATTRIBUTE attrTemplate[] = {
        { CKA_CLASS,            &objClass,  sizeof(objClass)    },
        { CKA_TOKEN,            &isToken,   sizeof(isToken)     },
        { CKA_CERTIFICATE_TYPE, &certType,  sizeof(certType)    }
    };

    result = C_FindObjectsInit(hSession, attrTemplate, 3);
    if (result != CKR_OK)
    {
        _RPT1(_CRT_WARN, "Error occurred during C_FindObjectsInit. Code 0x%x\n", result);
        return EPSIF_E_CANNOT_FIND_OBJECTS;
    }

    result = C_FindObjects(hSession, &obj, 1, &ulObjCount);
    if (result != CKR_OK)
    {
        _RPT1(_CRT_WARN, "Error occurred during C_FindObjects. Code 0x%x\n", result);
        return EPSIF_E_CANNOT_FIND_OBJECTS;
    }

    result = C_FindObjectsFinal(hSession);
    if (result != CKR_OK)
    {
        _RPT1(_CRT_WARN, "Error occurred during C_FindObjectsFinal. Code 0x%x\n", result);
        return EPSIF_E_CANNOT_FIND_OBJECTS;
    }

    // Check if we got any certificate
    if (ulObjCount == 0) { return EPSIF_E_NO_CERTIFICATES; }

    // We got a certificate
    return S_OK;
}

// ------------------------------------------------------
//
// Get a certificate from the "My" system store.
// 
// ------------------------------------------------------
HRESULT GetCertificateFromMyStore(BSTR pwszCertificateName, PCCERT_CONTEXT &pCertificate)
{
    // NOTE: Here a decision has been made to detach this method from
    //  being tied to the CryptoKi library, as it can be used without
    //  the ePass2003 PKI token.
    // assert(g_IsInitialized == true);

    HRESULT hr{ S_OK };

    HCERTSTORE hMySysStore{ nullptr };
    PCCERT_CONTEXT pCert{ nullptr };

    // === Open the "My" system store ===
    hMySysStore = CertOpenSystemStore(NULL, L"MY");
    if (!hMySysStore)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto done;
    }

    // === Find the certificate in the store ===
    pCert = CertFindCertificateInStore(hMySysStore, X509_ASN_ENCODING, 0, CERT_FIND_ISSUER_STR, pwszCertificateName, nullptr);
    if (!pCert)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto done;
    }

    pCertificate = pCert;

done:
    if (FAILED(hr) && pCert)
    {
        CertFreeCertificateContext(pCert);
    }

    if (hMySysStore)
    {
        CertCloseStore(hMySysStore, 0);
    }

    return hr;
}
