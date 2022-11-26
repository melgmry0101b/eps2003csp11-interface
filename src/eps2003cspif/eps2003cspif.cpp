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
HRESULT CheckAnyCertificatePresent(CK_SESSION_HANDLE hSession);

// ==============================
// ====== Exported Methods ======
// ==============================

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

    // === Convert Passed Strings ===
    if (wcstombs_s(&pinLen, mbPin, MAX_BUFFER, pwszPin, MAX_BUFFER - 1) != ERROR_SUCCESS)
    {
        return E_UNEXPECTED;
    }

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
    hr = CheckAnyCertificatePresent(g_hSession);
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
// Check if a certificate is present.
// 
// ------------------------------------------------------
HRESULT CheckAnyCertificatePresent(CK_SESSION_HANDLE hSession)
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
