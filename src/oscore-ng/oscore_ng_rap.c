/*
 * oscore_ng_rap.c -- Helpers for remote attestations
 *
 * Copyright (C) 2025 Siemens AG
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file oscore_ng_rap.c
 * @brief Helpers for remote attestations
 */

#include "coap3/coap_libcoap_build.h"
#include <string.h>

size_t
rap_get_reg_requests_payload_size(rap_reg_request_t *reg_request) {
  return CBOR_BYTE_STRING_SIZE(reg_request->cookie_size)
         + CBOR_BYTE_STRING_SIZE(
             sizeof(reg_request->ephemeral_public_key_compressed))
         + reg_request->out_cert_chain.length
         + (reg_request->tee_tci_version
            ? CBOR_UNSIGNED_SIZE(reg_request->tee_tci_version)
            : 0);
}

int
rap_write_reg_request(rap_reg_request_t *reg_request,
                      uint8_t *payload,
                      size_t max_payload_size) {
  cbor_writer_state_t state;

  cbor_init_writer(&state, payload, max_payload_size);

  /* append cookie */
  cbor_write_data(&state, reg_request->cookie, reg_request->cookie_size);

  /* append ephemeral public key */
  tiny_dice_write_compressed_public_key(
      &state,
      reg_request->ephemeral_public_key_compressed);

  /* append certificate chain */
  cbor_write_object(&state,
                    reg_request->out_cert_chain.s,
                    reg_request->out_cert_chain.length);

  /* append TCI */
  if (reg_request->tee_tci_version) {
    cbor_write_unsigned(&state, reg_request->tee_tci_version);
  }

  return max_payload_size == cbor_end_writer(&state);
}

int
rap_parse_reg_request(rap_reg_request_t *reg_request,
                      const uint8_t *payload,
                      size_t payload_size) {
  cbor_reader_state_t state;
  cbor_init_reader(&state, payload, payload_size);

  /* parse cookie */
  reg_request->cookie = cbor_read_data(&state, &reg_request->cookie_size);
  if (!reg_request->cookie) {
    return 0;
  }

  /* parse ephemeral public key */
  if (!tiny_dice_parse_compressed_public_key(
          &state,
          reg_request->ephemeral_public_key_compressed)) {
    return 0;
  }

  /* parse certificate chain */
  switch (cbor_peek_next(&state)) {
  case CBOR_MAJOR_TYPE_NONE:
    reg_request->in_cert_chain.length = 0;
    break;
  case CBOR_MAJOR_TYPE_ARRAY:
    if (tiny_dice_decode_cert_chain(&state,
                                    &reg_request->in_cert_chain) == SIZE_MAX) {
      return 0;
    }
    break;
  case CBOR_MAJOR_TYPE_UNSIGNED:
  case CBOR_MAJOR_TYPE_BYTE_STRING:
  case CBOR_MAJOR_TYPE_TEXT_STRING:
  case CBOR_MAJOR_TYPE_MAP:
  case CBOR_MAJOR_TYPE_SIMPLE:
  default:
    return 0;
  }

  /* parse TCI */
  switch (cbor_peek_next(&state)) {
  case CBOR_MAJOR_TYPE_NONE:
    reg_request->tee_tci_version = 0;
    break;
  case CBOR_MAJOR_TYPE_UNSIGNED: {
    uint64_t value;
    if ((cbor_read_unsigned(&state, &value) == CBOR_SIZE_NONE)
        || (value > UINT32_MAX)) {
      return 0;
    }
    reg_request->tee_tci_version = value;
    break;
  }
  case CBOR_MAJOR_TYPE_BYTE_STRING:
  /* TODO support in-line TCI */
  case CBOR_MAJOR_TYPE_TEXT_STRING:
  case CBOR_MAJOR_TYPE_ARRAY:
  case CBOR_MAJOR_TYPE_MAP:
  case CBOR_MAJOR_TYPE_SIMPLE:
  default:
    return 0;
  }
  return cbor_end_reader(&state);
}

int
rap_parse_reg_response(const uint8_t *payload,
                       size_t payload_size,
                       rap_reg_response_t *reg_response) {
  cbor_reader_state_t state;
  if (payload_size < sizeof(reg_response->oscore_ng_mic)) {
    return 0;
  }
  payload_size -= sizeof(reg_response->oscore_ng_mic);
  memcpy(reg_response->oscore_ng_mic,
         payload + payload_size,
         sizeof(reg_response->oscore_ng_mic));
  cbor_init_reader(&state, payload, payload_size);

  /* parse ephemeral public key */
  if (!tiny_dice_parse_compressed_public_key(
          &state,
          reg_response->ephemeral_public_key_compressed)) {
    return 0;
  }

  /* parse certificate chain */
  if (tiny_dice_decode_cert_chain(&state,
                                  &reg_response->cert_chain) == SIZE_MAX) {
    return 0;
  }

  /* parse TEE's TCI */
  switch (cbor_peek_next(&state)) {
  case CBOR_MAJOR_TYPE_NONE:
    reg_response->tee_tci_version = 0;
    break;
  case CBOR_MAJOR_TYPE_UNSIGNED: {
    uint64_t value;
    if ((cbor_read_unsigned(&state, &value) == CBOR_SIZE_NONE)
        || (value > UINT32_MAX)) {
      return 0;
    }
    reg_response->tee_tci_version = value;
    break;
  }
  case CBOR_MAJOR_TYPE_BYTE_STRING:
  /* TODO support in-line TCI */
  case CBOR_MAJOR_TYPE_TEXT_STRING:
  case CBOR_MAJOR_TYPE_ARRAY:
  case CBOR_MAJOR_TYPE_MAP:
  case CBOR_MAJOR_TYPE_SIMPLE:
  default:
    return 0;
  }
  return cbor_end_reader(&state);
}
