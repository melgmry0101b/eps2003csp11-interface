/*-----------------------------------------------------------------*\
 *
 * errcodes.h
 *   eps2003cspif
 *     eps2003csp11-interface
 *
 * MIT - see LICENSE at root directory
 *
 * CREATED: 2022-11-25 01:21 PM
 * AUTHORS: Mohammed Elghamry <elghamry.connect[at]outlook[dot]com>
 *
\*-----------------------------------------------------------------*/

#ifndef EPS2003CSPIF_ERRCODES_H
#define EPS2003CSPIF_ERRCODES_H

// ====================
// ====== Macros ======
// ====================

#define MAKE_ITF_ERROR_HRESULT(code) MAKE_HRESULT(SEVERITY_ERROR, FACILITY_ITF, code)

// =========================
// ====== Error Codes ======
// =========================

// Base error code for the application
#define _EPSIF_BASE_ERROR_CODE 0x200

#define _EPSIF_ECODE_INIT_FAILED            (_EPSIF_BASE_ERROR_CODE + 0x000)
#define _EPSIF_ECODE_FINALIZE_FAILED        (_EPSIF_BASE_ERROR_CODE + 0x001)
#define _EPSIF_ECODE_NOT_INITIALIZED        (_EPSIF_BASE_ERROR_CODE + 0x002)
#define _EPSIF_ECODE_CANNOT_GET_SLOTS       (_EPSIF_BASE_ERROR_CODE + 0x003)
#define _EPSIF_ECODE_NO_SLOTS_FOUND         (_EPSIF_BASE_ERROR_CODE + 0x004)
#define _EPSIF_ECODE_OPEN_SESSION_FAILED    (_EPSIF_BASE_ERROR_CODE + 0x005)
#define _EPSIF_ECODE_LOGIN_FAILED           (_EPSIF_BASE_ERROR_CODE + 0x006)
#define _EPSIF_ECODE_CANNOT_FIND_OBJECTS    (_EPSIF_BASE_ERROR_CODE + 0x007)
#define _EPSIF_ECODE_NO_CERTIFICATES        (_EPSIF_BASE_ERROR_CODE + 0x008)

// =====================
// ====== HRESULT ======
// =====================

//
// Initialization failed
//
#define EPSIF_E_INIT_FAILED             MAKE_ITF_ERROR_HRESULT(_EPSIF_ECODE_INIT_FAILED)

//
// Finalization failed
//
#define EPSIF_E_FINALIZE_FAILED         MAKE_ITF_ERROR_HRESULT(_EPSIF_ECODE_FINALIZE_FAILED)

//
// Requested an operation on a non-initialized library
//
#define EPSIF_E_NOT_INITIALIZED         MAKE_ITF_ERROR_HRESULT(_EPSIF_ECODE_NOT_INITIALIZED)

//
// Cannot get slots
//
#define EPSIF_E_CANNOT_GET_SLOTS        MAKE_ITF_ERROR_HRESULT(_EPSIF_ECODE_CANNOT_GET_SLOTS)

//
// No slots with token found
//
#define EPSIF_E_NO_SLOTS_FOUND          MAKE_ITF_ERROR_HRESULT(_EPSIF_ECODE_NO_SLOTS_FOUND)

//
// Opening session for a slot failed
//
#define EPSIF_E_OPEN_SESSION_FAILED     MAKE_ITF_ERROR_HRESULT(_EPSIF_ECODE_OPEN_SESSION_FAILED);

//
// Login failed.
//
#define EPSIF_E_LOGIN_FAILED            MAKE_ITF_ERROR_HRESULT(_EPSIF_ECODE_LOGIN_FAILED);

//
// Cannot find objects
//
#define EPSIF_E_CANNOT_FIND_OBJECTS     MAKE_ITF_ERROR_HRESULT(_EPSIF_ECODE_CANNOT_FIND_OBJECTS);

//
// No certificates found
//
#define EPSIF_E_NO_CERTIFICATES         MAKE_ITF_ERROR_HRESULT(_EPSIF_ECODE_NO_CERTIFICATES);

#endif
