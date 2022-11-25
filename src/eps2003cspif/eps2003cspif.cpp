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

// =====================
// ====== Globals ======
// =====================

static bool g_IsInitialized{ false };

// ==============================
// ====== Exported Methods ======
// ==============================

// ------------------------------------------------------
// 
// Initialize the library for operations.
// 
// ------------------------------------------------------
DLLENTRY(HRESULT) Initialize()
{
    if (g_IsInitialized) { return S_OK; }

    CK_RV result{ CKR_OK };

    // Send initialization command to the library
    result = C_Initialize(nullptr);
    if (result != CKR_OK && result != CKR_CRYPTOKI_ALREADY_INITIALIZED)
    {
        _RPT1(_CRT_WARN, "Error occurred during initialization, code 0x%x", result);
        return EPSIF_E_INIT_FAILED;
    }

    g_IsInitialized = true;

    return S_OK;
}
