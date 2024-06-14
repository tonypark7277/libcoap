/*
 * oscore_ng_tiny_dice.h -- TinyDICE helpers
 *
 * Copyright (C) 2025 Siemens AG
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file oscore_ng_tiny_dice.h
 * @brief TinyDICE helpers
 */

#ifndef OSCORE_NG_TINY_DICE_H_
#define OSCORE_NG_TINY_DICE_H_

/**
 * @ingroup internal_api
 * @defgroup tiny_dice TinyDICE
 * Internal API for TinyDICE
 * @{
 */

#include <stddef.h>
#include <stdint.h>

#ifndef TINY_DICE_UDS_SIZE
#define TINY_DICE_UDS_SIZE SHA_256_DIGEST_LENGTH
#endif /* TINY_DICE_UDS_SIZE */

#ifndef TINY_DICE_CDI_SIZE
#define TINY_DICE_CDI_SIZE SHA_256_DIGEST_LENGTH
#endif /* TINY_DICE_CDI_SIZE */

#ifndef TINY_DICE_TCI_SIZE
#define TINY_DICE_TCI_SIZE SHA_256_DIGEST_LENGTH
#endif /* TINY_DICE_TCI_SIZE */

#ifndef TINY_DICE_ISSUER_ID_SIZE
#define TINY_DICE_ISSUER_ID_SIZE SHA_256_DIGEST_LENGTH
#endif /* TINY_DICE_ISSUER_ID_SIZE */

#ifndef TINY_DICE_MAX_CURVE_SIZE
#define TINY_DICE_MAX_CURVE_SIZE ECC_CURVE_P_256_SIZE
#endif /* TINY_DICE_MAX_CURVE_SIZE */

#ifndef TINY_DICE_MAX_CERT_SIZE
#define TINY_DICE_MAX_CERT_SIZE \
  ((CBOR_UNSIGNED_SIZE(5) * 5) \
   + CBOR_BYTE_STRING_SIZE(CBOR_SIZE_1 - 1) \
   + CBOR_BYTE_STRING_SIZE(TINY_DICE_ISSUER_ID_SIZE) \
   + CBOR_BYTE_STRING_SIZE(1 + TINY_DICE_MAX_CURVE_SIZE) \
   + CBOR_BYTE_STRING_SIZE(TINY_DICE_TCI_SIZE))
#endif /* TINY_DICE_MAX_CERT_SIZE */

#ifndef TINY_DICE_MAX_CERT_CHAIN_LENGTH
#define TINY_DICE_MAX_CERT_CHAIN_LENGTH (2)
#endif /* TINY_DICE_MAX_CERT_CHAIN_LENGTH */

#ifndef TINY_DICE_MAX_CERT_CHAIN_SIZE
#define TINY_DICE_MAX_CERT_CHAIN_SIZE (TINY_DICE_MAX_CERT_CHAIN_LENGTH \
                                       * TINY_DICE_MAX_CERT_SIZE)
#endif /* TINY_DICE_MAX_CERT_CHAIN_SIZE */

/**
 * IDs of approved curves.
 */
typedef enum tiny_dice_curve_t {
  TINY_DICE_CURVE_SECP192K1 = 0,
  TINY_DICE_CURVE_SECP192R1,
  TINY_DICE_CURVE_SECP224K1,
  TINY_DICE_CURVE_SECP224R1,
  TINY_DICE_CURVE_SECP256K1,
  TINY_DICE_CURVE_SECP256R1,
  TINY_DICE_CURVE_SECP384R1,
  TINY_DICE_CURVE_SECP512R1,
  TINY_DICE_CURVE_SECT163K1,
  TINY_DICE_CURVE_SECT163R1,
  TINY_DICE_CURVE_SECT233K1,
  TINY_DICE_CURVE_SECT233R1,
  TINY_DICE_CURVE_SECT239K1,
  TINY_DICE_CURVE_SECT283K1,
  TINY_DICE_CURVE_SECT283R1,
  TINY_DICE_CURVE_SECT409K1,
  TINY_DICE_CURVE_SECT409R1,
  TINY_DICE_CURVE_SECT571K1,
  TINY_DICE_CURVE_SECT571R1,
  TINY_DICE_CURVE_MAX,
} tiny_dice_curve_t;

/**
 * IDs of approved cryptographic hash functions.
 */
typedef enum tiny_dice_hash_t {
  TINY_DICE_HASH_SHA224 = 0,
  TINY_DICE_HASH_SHA256,
  TINY_DICE_HASH_SHA384,
  TINY_DICE_HASH_SHA512,
  TINY_DICE_HASH_MAX,
} tiny_dice_hash_t;

/**
 * Structure of a TinyDICE certificate.
 */
typedef struct tiny_dice_cert_t {
  const uint8_t *subject_data; /* NULL denotes unset */
  const char *subject_text; /* NULL denotes unset */
  size_t subject_size;
  tiny_dice_hash_t issuer_hash; /* in a root certificate */
  const uint8_t *issuer_id; /* in an inferior certificate */
  tiny_dice_curve_t curve;
  uint8_t reconstruction_data[1 + TINY_DICE_MAX_CURVE_SIZE];
  const uint8_t *tci_digest; /* NULL denotes unset */
  uint32_t tci_version; /* 0 denotes unset */
} tiny_dice_cert_t;

/**
 * Structure of a TinyDICE certificate chain.
 */
typedef struct tiny_dice_cert_chain_t {
  size_t length;
  tiny_dice_cert_t certs[TINY_DICE_MAX_CERT_CHAIN_LENGTH];
} tiny_dice_cert_chain_t;

/**
 * A mapping between a full TCI and a version number.
 */
typedef struct tiny_dice_tci_mapping_t {
  const uint8_t *digest;
  uint32_t version;
} tiny_dice_tci_mapping_t;

/**
 * Initializes a TinyDICE certificate with default values.
 *
 * @param cert  The TinyDICE certificate.
 */
void tiny_dice_clear_cert(tiny_dice_cert_t *cert);

/**
 * Appends a TinyDICE certificate to a CBOR output.
 *
 * @param state CBOR output.
 * @param cert  The TinyDICE certificate.
 */
void tiny_dice_write_cert(cbor_writer_state_t *state,
                          const tiny_dice_cert_t *cert);

/**
 * Appends a TinyDICE certificate chain to a CBOR output.
 *
 * @param state      CBOR output.
 * @param cert_chain The TinyDICE certificate chain.
 */
void tiny_dice_write_cert_chain(cbor_writer_state_t *state,
                                tiny_dice_cert_chain_t *cert_chain);

/**
 * Parses a TinyDICE certificate.
 *
 * @param state CBOR input.
 * @param cert  A certificate for storing parsed contents.
 *
 * @return      @c 1 on success, or @c 0 otherwise.
 */
int tiny_dice_decode_cert(cbor_reader_state_t *state, tiny_dice_cert_t *cert);

/**
 * Parses a TinyDICE certificate chain.
 *
 * @param state      CBOR input.
 * @param cert_chain A certificate chain for storing parsed contents.
 *
 * @return           Number of parsed certificates, or @c SIZE_MAX on error.
 */
size_t tiny_dice_decode_cert_chain(cbor_reader_state_t *state,
                                   tiny_dice_cert_chain_t *cert_chain);

/**
 * Compresses entries of a TinyDICE certificate chain.
 *
 * @param tci_l1_mapping TCI <-> version mapping for Layer 1 (NULLable).
 * @param cert_chain     The compressed TinyDICE certificate chain.
 */
void tiny_dice_compress_cert_chain(const tiny_dice_tci_mapping_t *tci_l1_mapping,
                                   tiny_dice_cert_chain_t *cert_chain);

/**
 * Decompresses entries of a TinyDICE certificate chain.
 *
 * @param subject_data   ID of the subject (NULLable).
 * @param subject_text   Name of the subject (NULLable).
 * @param subject_size   Size of the subject value in bytes.
 * @param tci_l1_mapping TCI <-> version mapping for Layer 1 (NULLable).
 * @param cert_chain     The decompressed TinyDICE certificate chain.
 */
void tiny_dice_decompress_cert_chain(const uint8_t *subject_data,
                                     const char *subject_text,
                                     size_t subject_size,
                                     const tiny_dice_tci_mapping_t *tci_l1_mapping,
                                     tiny_dice_cert_chain_t *cert_chain);

/**
 * Appends a compressed public key to a CBOR output.
 *
 * @param state                 CBOR output.
 * @param compressed_public_key The compressed public key in SECG SEC 1 format.
 */
void tiny_dice_write_compressed_public_key(
    cbor_writer_state_t *state,
    const uint8_t *compressed_public_key);

/**
 * Parses a compressed public key.
 *
 * @param state                 CBOR input.
 * @param compressed_public_key The compressed public key in SECG SEC 1 format.
 *
 * @return                      @c 1 on success, or @c 0 otherwise.
 */
int tiny_dice_parse_compressed_public_key(cbor_reader_state_t *state,
                                          uint8_t *compressed_public_key);

/** @} */

#endif /* OSCORE_NG_TINY_DICE_H_ */
