/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "ESSSigningCertificateV2Module"
 * 	found in "ESSSigningCertificateV2.asn1"
 * 	`asn1c -pdu=SigningCertificateV2`
 */

#include "GeneralNames.h"

static asn_TYPE_member_t asn_MBR_GeneralNames_1[] = {
	{ ATF_POINTER, 0, 0,
		-1 /* Ambiguous tag (CHOICE?) */,
		0,
		&asn_DEF_GeneralName,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		""
		},
};
static const ber_tlv_tag_t asn_DEF_GeneralNames_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_GeneralNames_specs_1 = {
	sizeof(struct GeneralNames),
	offsetof(struct GeneralNames, _asn_ctx),
	2,	/* XER encoding is XMLValueList */
};
asn_TYPE_descriptor_t asn_DEF_GeneralNames = {
	"GeneralNames",
	"GeneralNames",
	SEQUENCE_OF_free,
	SEQUENCE_OF_print,
	SEQUENCE_OF_constraint,
	SEQUENCE_OF_decode_ber,
	SEQUENCE_OF_encode_der,
	SEQUENCE_OF_decode_xer,
	SEQUENCE_OF_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_GeneralNames_tags_1,
	sizeof(asn_DEF_GeneralNames_tags_1)
		/sizeof(asn_DEF_GeneralNames_tags_1[0]), /* 1 */
	asn_DEF_GeneralNames_tags_1,	/* Same as above */
	sizeof(asn_DEF_GeneralNames_tags_1)
		/sizeof(asn_DEF_GeneralNames_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_GeneralNames_1,
	1,	/* Single element */
	&asn_SPC_GeneralNames_specs_1	/* Additional specs */
};

