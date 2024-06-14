/* libcoap unit tests
 *
 * Copyright (C) 2025 Siemens AG
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#include "test_common.h"

#if COAP_OSCORE_NG_SUPPORT
#include "test_tiny_dice.h"
#include "oscore-ng/oscore_ng_tiny_dice.h"

#include <string.h>
#include <unistd.h>

static const uint8_t subject[CBOR_SIZE_1 - 1] = { 0xA, 0xB };
static const uint8_t issuer[TINY_DICE_ISSUER_ID_SIZE] = { 0x0A, 0x0B, 0x0C, };
static const uint8_t reconstruction_data[1 + ECC_CURVE_P_256_SIZE] = {
  0x03,
  0xEA, 0x8B, 0xCF, 0xD6, 0x3A, 0x21, 0x2E, 0x04,
  0x68, 0xF6, 0x96, 0x5B, 0x3F, 0x3B, 0x15, 0x31,
  0x7C, 0xE5, 0xC7, 0xC2, 0xF1, 0x0C, 0xB1, 0xD3,
  0x28, 0x77, 0x80, 0xB6, 0xC7, 0xFC, 0xF6, 0x88
};
static uint8_t tci[TINY_DICE_TCI_SIZE] = { 0x01, 0x02, 0x03, };

/************************************************************************
 ** tests
 ************************************************************************/

static void
t_tiny_dice_l0(void) {
  tiny_dice_cert_t cert;
  uint8_t certificate[TINY_DICE_MAX_CERT_SIZE];
  size_t certificate_size;

  /* initialize exemplary Cert_L0 */
  tiny_dice_clear_cert(&cert);
  cert.subject_data = subject;
  cert.subject_size = sizeof(subject);
  memcpy(cert.reconstruction_data,
         reconstruction_data,
         sizeof(reconstruction_data));
  cert.tci_version = 1;

  /* write Cert_L0 */
  {
    cbor_writer_state_t writer_state;

    cbor_init_writer(&writer_state, certificate, sizeof(certificate));
    tiny_dice_write_cert(&writer_state, &cert);
    certificate_size = cbor_end_writer(&writer_state);
    CU_ASSERT(certificate_size);
  }

  /* parse Cert_L0 */
  {
    cbor_reader_state_t reader_state;

    cbor_init_reader(&reader_state, certificate, certificate_size);
    CU_ASSERT(tiny_dice_decode_cert(&reader_state, &cert));
    CU_ASSERT(cbor_end_reader(&reader_state));
  }

  /* compare with the original contents */
  CU_ASSERT(cert.subject_size == sizeof(subject));
  CU_ASSERT(!memcmp(subject, cert.subject_data, sizeof(subject)));
  CU_ASSERT(cert.issuer_hash == TINY_DICE_HASH_SHA256);
  CU_ASSERT(!cert.issuer_id);
  CU_ASSERT(cert.curve == TINY_DICE_CURVE_SECP256R1);
  CU_ASSERT(!memcmp(cert.reconstruction_data,
                    reconstruction_data,
                    sizeof(reconstruction_data)));
  CU_ASSERT(!cert.tci_digest && (cert.tci_version == 1));
}

static void
t_tiny_dice_l1(void) {
  tiny_dice_cert_t cert;
  uint8_t certificate[TINY_DICE_MAX_CERT_SIZE];
  size_t certificate_size;

  /* initialize exemplary Cert_L1 */
  tiny_dice_clear_cert(&cert);
  memcpy(cert.reconstruction_data,
         reconstruction_data,
         sizeof(reconstruction_data));
  cert.tci_digest = tci;

  /* write Cert_L1 */
  {
    cbor_writer_state_t writer_state;

    cbor_init_writer(&writer_state, certificate, sizeof(certificate));
    tiny_dice_write_cert(&writer_state, &cert);
    certificate_size = cbor_end_writer(&writer_state);
    CU_ASSERT(certificate_size);
  }

  /* parse Cert_L1 */
  {
    cbor_reader_state_t reader_state;

    cbor_init_reader(&reader_state, certificate, certificate_size);
    CU_ASSERT(tiny_dice_decode_cert(&reader_state, &cert));
    CU_ASSERT(cbor_end_reader(&reader_state));
  }

  /* compare with the original contents */
  CU_ASSERT(!cert.subject_size && !cert.subject_data && !cert.subject_text);
  CU_ASSERT(cert.issuer_hash == TINY_DICE_HASH_SHA256);
  CU_ASSERT(!cert.issuer_id);
  CU_ASSERT(cert.curve == TINY_DICE_CURVE_SECP256R1);
  CU_ASSERT(!memcmp(cert.reconstruction_data,
                    reconstruction_data,
                    sizeof(reconstruction_data)));
  CU_ASSERT(!memcmp(tci, cert.tci_digest, sizeof(tci)));
}

static void
t_tiny_dice_curve(void) {
  tiny_dice_cert_t cert;
  uint8_t certificate[TINY_DICE_MAX_CERT_SIZE];
  size_t certificate_size;

  /* init certificate with a non-standard curve */
  tiny_dice_clear_cert(&cert);
  cert.curve = TINY_DICE_CURVE_SECT571R1;
  memcpy(cert.reconstruction_data,
         reconstruction_data,
         sizeof(reconstruction_data));
  cert.tci_digest = tci;

  /* write certificate */
  {
    cbor_writer_state_t writer_state;

    cbor_init_writer(&writer_state, certificate, sizeof(certificate));
    tiny_dice_write_cert(&writer_state, &cert);
    certificate_size = cbor_end_writer(&writer_state);
    CU_ASSERT(certificate_size);
  }

  /* parse certificate */
  {
    cbor_reader_state_t reader_state;
    cbor_init_reader(&reader_state, certificate, certificate_size);
    CU_ASSERT(tiny_dice_decode_cert(&reader_state, &cert));
    CU_ASSERT(cbor_end_reader(&reader_state));
  }

  /* compare with the original contents */
  CU_ASSERT(cert.curve == TINY_DICE_CURVE_SECT571R1);
}

static void
t_tiny_dice_issuer(void) {
  tiny_dice_cert_t cert;
  uint8_t certificate[TINY_DICE_MAX_CERT_SIZE];
  size_t certificate_size;

  /* init certificate with an issuer entry */
  tiny_dice_clear_cert(&cert);
  cert.issuer_id = issuer;
  memcpy(cert.reconstruction_data,
         reconstruction_data,
         sizeof(reconstruction_data));
  cert.tci_digest = tci;

  /* write certificate */
  {
    cbor_writer_state_t writer_state;

    cbor_init_writer(&writer_state, certificate, sizeof(certificate));
    tiny_dice_write_cert(&writer_state, &cert);
    certificate_size = cbor_end_writer(&writer_state);
    CU_ASSERT(certificate_size);
  }

  /* parse certificate */
  {
    cbor_reader_state_t reader_state;
    cbor_init_reader(&reader_state, certificate, certificate_size);
    CU_ASSERT(tiny_dice_decode_cert(&reader_state, &cert));
    CU_ASSERT(cbor_end_reader(&reader_state));
  }

  /* compare with the original contents */
  CU_ASSERT(!memcmp(issuer, cert.issuer_id, sizeof(issuer)));
}

static void
t_tiny_dice_max_cert(void) {
  tiny_dice_cert_t cert;
  uint8_t certificate[TINY_DICE_MAX_CERT_SIZE];
  cbor_writer_state_t writer_state;

  /* init certificate with an issuer entry */
  tiny_dice_clear_cert(&cert);
  cert.subject_data = subject;
  cert.subject_size = sizeof(subject);
  cert.issuer_id = issuer;
  memcpy(cert.reconstruction_data,
         reconstruction_data,
         sizeof(reconstruction_data));
  cert.tci_digest = tci;

  /* write certificate */
  cbor_init_writer(&writer_state, certificate, sizeof(certificate));
  tiny_dice_write_cert(&writer_state, &cert);
  CU_ASSERT(cbor_end_writer(&writer_state));

  /* write certificate */
  cbor_init_writer(&writer_state, certificate, sizeof(certificate) - 1);
  tiny_dice_write_cert(&writer_state, &cert);
  CU_ASSERT(!cbor_end_writer(&writer_state));
}

/************************************************************************
 ** initialization
 ************************************************************************/

CU_pSuite
t_init_tiny_dice_tests(void) {
  CU_pSuite suite[5];

  suite[0] = CU_add_suite("TinyDICE", NULL, NULL);
  if (!suite[0]) {                        /* signal error */
    fprintf(stderr, "W: cannot add TinyDICE test suite (%s)\n",
            CU_get_error_msg());

    return NULL;
  }

#define TINY_DICE_TEST(n)                                  \
  if (!CU_add_test(suite[0], #n, n)) {                     \
    fprintf(stderr, "W: cannot add OSCORE-NG test (%s)\n", \
            CU_get_error_msg());                           \
  }

  TINY_DICE_TEST(t_tiny_dice_l0);
  TINY_DICE_TEST(t_tiny_dice_l1);
  TINY_DICE_TEST(t_tiny_dice_curve);
  TINY_DICE_TEST(t_tiny_dice_issuer);
  TINY_DICE_TEST(t_tiny_dice_max_cert);

  return suite[0];
}

#else /* COAP_OSCORE_NG_SUPPORT */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void
dummy(void) {
}

#endif /* COAP_OSCORE_NG_SUPPORT */
