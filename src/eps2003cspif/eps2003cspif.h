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
// Initialize the library for operations.
// ------------------------------------------------------
DLLENTRY(HRESULT) Initialize();

#endif //EPS2003CSPIF_H
