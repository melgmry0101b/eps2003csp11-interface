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

// Base error code for the application
#define _EPSIF_BASE_ERROR_CODE 0x200

// =========================
// ====== Error Codes ======
// =========================

#define _EPSIF_ECODE_INIT_FAILED        (_EPSIF_BASE_ERROR_CODE + 0x000)
#define _EPSIF_ECODE_FINALIZE_FAILED    (_EPSIF_BASE_ERROR_CODE + 0x001)

// =====================
// ====== HRESULT ======
// =====================

//
// Initialization failed
//
#define EPSIF_E_INIT_FAILED         MAKE_HRESULT(SEVERITY_ERROR, FACILITY_ITF, _EPSIF_ECODE_INIT_FAILED)

//
// Finalization failed
//
#define EPSIF_E_FINALIZE_FAILED     MAKE_HRESULT(SEVERITY_ERROR, FACILITY_ITF, _EPSIF_ECODE_FINALIZE_FAILED)

#endif
