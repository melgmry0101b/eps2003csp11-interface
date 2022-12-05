/*-----------------------------------------------------------------*\
 *
 * cmssign.h
 *   eps2003cspif
 *     eps2003csp11-interface
 *
 * MIT - see LICENSE at root directory
 *
 * CREATED: 2022-12-3 12:26 PM
 * AUTHORS: Mohammed Elghamry <elghamry.connect[at]outlook[dot]com>
 *
\*-----------------------------------------------------------------*/

#ifndef EPS2003CSPIF_CMSSIGN_H
#define EPS2003CSPIF_CMSSIGN_H

// ------------------------------------------------------
// Create CAdES-BES message for content with one signer.
// ------------------------------------------------------
HRESULT CreateCadesBesSignedMessage(
    BYTE *pbContent,
    DWORD cbContent,
    PCCERT_CONTEXT pCert,
    BYTE **ppbEncodedBlob,
    DWORD *pcbEncodedBlob);

#endif //EPS2003CSPIF_CMSSIGN_H
