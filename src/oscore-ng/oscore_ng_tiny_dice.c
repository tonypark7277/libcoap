/*
 * oscore_ng_tiny_dice.c -- TinyDICE helpers
 *
 * Copyright (C) 2025 Siemens AG
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file oscore_ng_tiny_dice.c
 * @brief TinyDICE helpers
 */

#include "coap3/coap_libcoap_build.h"
#ifdef KEYSTONE_BOOTLOADER
#include "string.h"
#elif defined(KEYSTONE_SM)
#include <sbi/sbi_string.h>
#define memcpy sbi_memcpy
#define memset sbi_memset
#define memcmp sbi_memcmp
#else
#include <string.h>
#endif

typedef enum tiny_dice_label_t {
  TINY_DICE_LABEL_SUBJECT = 0,
  TINY_DICE_LABEL_ISSUER,
  TINY_DICE_LABEL_CURVE,
  TINY_DICE_LABEL_RECONSTRUCTION_DATA,
  TINY_DICE_LABEL_TCI,
  TINY_DICE_LABEL_MAX,
} tiny_dice_label_t;


void
tiny_dice_clear_cert(tiny_dice_cert_t *cert) {
  memset(cert, 0, sizeof(*cert));
  cert->issuer_hash = TINY_DICE_HASH_SHA256;
  cert->curve = TINY_DICE_CURVE_SECP256R1;
}

void
tiny_dice_write_cert(cbor_writer_state_t *state,
                     const tiny_dice_cert_t *cert) {
  cbor_open_map(state);

  /* subject */
  if (cert->subject_data || cert->subject_text) {
    cbor_write_unsigned(state, TINY_DICE_LABEL_SUBJECT);
    if (cert->subject_data) {
      cbor_write_data(state, cert->subject_data, cert->subject_size);
    } else {
      cbor_write_text(state, cert->subject_text, cert->subject_size);
    }
  }

  /* issuer */
  if ((cert->issuer_hash != TINY_DICE_HASH_SHA256) || cert->issuer_id) {
    cbor_write_unsigned(state, TINY_DICE_LABEL_ISSUER);
    if (cert->issuer_id) {
      cbor_write_data(state, cert->issuer_id, TINY_DICE_ISSUER_ID_SIZE);
    } else {
      cbor_write_unsigned(state, cert->issuer_hash);
    }
  }

  /* curve */
  if (cert->curve != TINY_DICE_CURVE_SECP256R1) {
    cbor_write_unsigned(state, TINY_DICE_LABEL_CURVE);
    cbor_write_unsigned(state, cert->curve);
  }

  /* public key reconstruction data */
  cbor_write_unsigned(state, TINY_DICE_LABEL_RECONSTRUCTION_DATA);
  tiny_dice_write_compressed_public_key(state, cert->reconstruction_data);

  /* TCI */
  cbor_write_unsigned(state, TINY_DICE_LABEL_TCI);
  if (cert->tci_digest) {
    cbor_write_data(state, cert->tci_digest, TINY_DICE_TCI_SIZE);
  } else if (cert->tci_version) {
    cbor_write_unsigned(state, cert->tci_version);
  } else {
    cbor_break_writer(state);
    return;
  }

  cbor_close_map(state);
}

void
tiny_dice_write_cert_chain(cbor_writer_state_t *state,
                           tiny_dice_cert_chain_t *cert_chain) {
  if (!cert_chain->length) {
    return;
  }
  cbor_open_array(state);
  for (size_t i = 0; i < cert_chain->length; i++) {
    tiny_dice_write_cert(state, cert_chain->certs + i);
  }
  cbor_close_array(state);
}

static tiny_dice_label_t
read_label(cbor_reader_state_t *state) {
  uint64_t value;
  if ((cbor_read_unsigned(state, &value) == CBOR_SIZE_NONE)
      || (value >= TINY_DICE_LABEL_MAX)) {
    return TINY_DICE_LABEL_MAX;
  }
  return value;
}

int
tiny_dice_decode_cert(cbor_reader_state_t *state, tiny_dice_cert_t *cert) {
  tiny_dice_clear_cert(cert);

  size_t pairs = cbor_read_map(state);
  if (pairs == SIZE_MAX) {
    return 0;
  }
  tiny_dice_label_t label = read_label(state);

  /* subject */
  if (label == TINY_DICE_LABEL_SUBJECT) {
    switch (cbor_peek_next(state)) {
    case CBOR_MAJOR_TYPE_BYTE_STRING:
      cert->subject_data = cbor_read_data(state, &cert->subject_size);
      if (!cert->subject_data) {
        return 0;
      }
      break;
    case CBOR_MAJOR_TYPE_TEXT_STRING:
      cert->subject_text = cbor_read_text(state, &cert->subject_size);
      if (!cert->subject_text) {
        return 0;
      }
      break;
    case CBOR_MAJOR_TYPE_NONE:
    case CBOR_MAJOR_TYPE_UNSIGNED:
    case CBOR_MAJOR_TYPE_ARRAY:
    case CBOR_MAJOR_TYPE_MAP:
    case CBOR_MAJOR_TYPE_SIMPLE:
    default:
      return 0;
    }
    if (!--pairs) {
      return 0;
    }
    label = read_label(state);
  }

  /* issuer */
  if (label == TINY_DICE_LABEL_ISSUER) {
    switch (cbor_peek_next(state)) {
    case CBOR_MAJOR_TYPE_UNSIGNED: {
      uint64_t value;
      if ((cbor_read_unsigned(state, &value) == CBOR_SIZE_NONE)
          || (value >= TINY_DICE_HASH_MAX)) {
        return 0;
      }
      cert->issuer_hash = value;
      break;
    }
    case CBOR_MAJOR_TYPE_BYTE_STRING: {
      size_t issuer_id_size;
      cert->issuer_id = cbor_read_data(state, &issuer_id_size);
      if (!cert->issuer_id || (issuer_id_size != TINY_DICE_ISSUER_ID_SIZE)) {
        return 0;
      }
      break;
    }
    case CBOR_MAJOR_TYPE_NONE:
    case CBOR_MAJOR_TYPE_ARRAY:
    case CBOR_MAJOR_TYPE_TEXT_STRING:
    case CBOR_MAJOR_TYPE_MAP:
    case CBOR_MAJOR_TYPE_SIMPLE:
    default:
      return 0;
    }
    if (!--pairs) {
      return 0;
    }
    label = read_label(state);
  }

  /* curve */
  if (label == TINY_DICE_LABEL_CURVE) {
    switch (cbor_peek_next(state)) {
    case CBOR_MAJOR_TYPE_UNSIGNED: {
      uint64_t value;
      if ((cbor_read_unsigned(state, &value) == CBOR_SIZE_NONE)
          || (value >= TINY_DICE_CURVE_MAX)) {
        return 0;
      }
      cert->curve = value;
      break;
    }
    case CBOR_MAJOR_TYPE_NONE:
    case CBOR_MAJOR_TYPE_BYTE_STRING:
    case CBOR_MAJOR_TYPE_TEXT_STRING:
    case CBOR_MAJOR_TYPE_ARRAY:
    case CBOR_MAJOR_TYPE_MAP:
    case CBOR_MAJOR_TYPE_SIMPLE:
    default:
      return 0;
    }
    if (!--pairs) {
      return 0;
    }
    label = read_label(state);
  }

  if (pairs != 2) {
    return 0;
  }

  /* public-key reconstruction data */
  if (label != TINY_DICE_LABEL_RECONSTRUCTION_DATA) {
    return 0;
  }
  tiny_dice_parse_compressed_public_key(state, cert->reconstruction_data);
  label = read_label(state);

  /* TCI */
  if (label != TINY_DICE_LABEL_TCI) {
    return 0;
  }

  switch (cbor_peek_next(state)) {
  case CBOR_MAJOR_TYPE_UNSIGNED: {
    uint64_t value;
    if ((cbor_read_unsigned(state, &value) == CBOR_SIZE_NONE)
        || (value > UINT32_MAX)) {
      return 0;
    }
    cert->tci_version = value;
    break;
  }
  case CBOR_MAJOR_TYPE_BYTE_STRING: {
    size_t tci_digest_size;
    cert->tci_digest = cbor_read_data(state, &tci_digest_size);
    if (!cert->tci_digest || (tci_digest_size != TINY_DICE_TCI_SIZE)) {
      return 0;
    }
    break;
  }
  case CBOR_MAJOR_TYPE_NONE:
  case CBOR_MAJOR_TYPE_TEXT_STRING:
  case CBOR_MAJOR_TYPE_ARRAY:
  case CBOR_MAJOR_TYPE_MAP:
  case CBOR_MAJOR_TYPE_SIMPLE:
  default:
    return 0;
  }

  return 1;
}

size_t
tiny_dice_decode_cert_chain(cbor_reader_state_t *state,
                            tiny_dice_cert_chain_t *cert_chain) {
  cert_chain->length = cbor_read_array(state);
  if (cert_chain->length > TINY_DICE_MAX_CERT_CHAIN_LENGTH) {
    return SIZE_MAX;
  }
  for (size_t i = 0; i < cert_chain->length; i++) {
    if (!tiny_dice_decode_cert(state, cert_chain->certs + i)) {
      return SIZE_MAX;
    }
  }
  return cert_chain->length;
}

static void
compress_cert(const tiny_dice_tci_mapping_t *tci_mapping,
              tiny_dice_cert_t *cert) {
  /* subject matches with OSCORE-NG Sender ID */
  cert->subject_data = NULL;
  cert->subject_text = NULL;
  cert->subject_size = 0;

  /* inferior certificates never need to spell out the issuer */
  cert->issuer_id = NULL;

  /* replace full TCI (if any) with a version number (if we have a mapping) */
  if (cert->tci_digest
      && tci_mapping
      && !memcmp(cert->tci_digest, tci_mapping->digest, TINY_DICE_TCI_SIZE)) {
    cert->tci_digest = NULL;
    cert->tci_version = tci_mapping->version;
  }
}

void
tiny_dice_compress_cert_chain(const tiny_dice_tci_mapping_t *tci_l1_mapping,
                              tiny_dice_cert_chain_t *cert_chain) {
  for (size_t i = 0; i < cert_chain->length; i++) {
    compress_cert((i == 1) || (cert_chain->length == 1) ? tci_l1_mapping : NULL,
                  cert_chain->certs + i);
  }
}

static void
decompress_cert(const uint8_t *subject_data,
                const char *subject_text,
                size_t subject_size,
                const tiny_dice_tci_mapping_t *tci_mapping,
                tiny_dice_cert_t *cert) {
  cert->subject_data = subject_data;
  cert->subject_text = subject_text;
  cert->subject_size = subject_size;

  /* restore in-line TCI */
  if (cert->tci_version
      && tci_mapping
      && (cert->tci_version == tci_mapping->version)) {
    cert->tci_digest = tci_mapping->digest;
    cert->tci_version = 0;
  }
}

void
tiny_dice_decompress_cert_chain(const uint8_t *subject_data,
                                const char *subject_text,
                                size_t subject_size,
                                const tiny_dice_tci_mapping_t *tci_l1_mapping,
                                tiny_dice_cert_chain_t *cert_chain) {
  for (size_t i = 0; i < cert_chain->length; i++) {
    decompress_cert(subject_data,
                    subject_text,
                    subject_size,
                    (i == 1) || (cert_chain->length == 1) ? tci_l1_mapping : NULL,
                    cert_chain->certs + i);
  }
}

void
tiny_dice_write_compressed_public_key(cbor_writer_state_t *state,
                                      const uint8_t *compressed_public_key) {
  cbor_write_data(state, compressed_public_key, 1 + ECC_CURVE_P_256_SIZE);
}

int
tiny_dice_parse_compressed_public_key(cbor_reader_state_t *state,
                                      uint8_t *compressed_public_key) {
  size_t data_size;
  const uint8_t *data = cbor_read_data(state, &data_size);
  if (!data
      || (data_size != (1 + ECC_CURVE_P_256_SIZE))
      || (data[0] & 0xFC)
      || !(data[0] & 2)) {
    return 0;
  }
  memcpy(compressed_public_key, data, data_size);
  return 1;
}
