/*-----------------------------------------------------------------*\
 *
 * framework.h
 *   eps2003cspif
 *     eps2003csp11-interface
 *
 * MIT - see LICENSE at root directory
 *
 * CREATED: 2022-11-24 05:51 PM
 * AUTHORS: Mohammed Elghamry <elghamry.connect[at]outlook[dot]com>
 *
\*-----------------------------------------------------------------*/

#ifndef EPS2003CSPIF_FRAMEWORK_H
#define EPS2003CSPIF_FRAMEWORK_H

// ==========================================
// ====== C++ Standard Library Headers ======
// ==========================================

#include <memory>
#include <cassert>
#include <cwchar>

// =================================
// ====== Windows API Headers ======
// =================================

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers

#include <windows.h>
#include <crtdbg.h>
#include <OleAuto.h>

// =====================
// ====== PKCS#11 ======
// =====================

#include <pkcs11/v2.20/cryptoki.h>

#endif //EPS2003CSPIF_FRAMEWORK_H

