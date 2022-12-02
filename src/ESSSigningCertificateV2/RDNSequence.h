/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "ESSSigningCertificateV2Module"
 * 	found in "ESSSigningCertificateV2.asn1"
 * 	`asn1c -pdu=SigningCertificateV2`
 */

#ifndef	_RDNSequence_H_
#define	_RDNSequence_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RelativeDistinguishedName;

/* RDNSequence */
typedef struct RDNSequence {
	A_SEQUENCE_OF(struct RelativeDistinguishedName) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RDNSequence_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RDNSequence;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "RelativeDistinguishedName.h"

#endif	/* _RDNSequence_H_ */
#include <asn_internal.h>
