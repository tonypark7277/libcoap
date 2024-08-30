/*
 * oscore_ng_rap.h -- Helpers for remote attestations
 *
 * Copyright (C) 2025 Siemens AG
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file oscore_ng_rap.h
 * @brief Helpers for remote attestations
 */

#ifndef OSCORE_NG_RAP_H_
#define OSCORE_NG_RAP_H_

#include "oscore-ng/oscore_ng_tiny_dice.h"

/**
 * @ingroup internal_api
 * @defgroup rap IRAP
 * Helpers for remote attestations
 * @{
 */

/**
 * Structure of a /reg request.
 */
typedef struct rap_reg_request_t {
  const uint8_t *cookie;
  size_t cookie_size;
  uint8_t ephemeral_public_key_compressed[1 + ECC_CURVE_P_256_SIZE];
  coap_bin_const_t out_cert_chain; /**< Only used when writing. */
  tiny_dice_cert_chain_t in_cert_chain; /**< Only used when reading. */
  uint32_t tee_tci_version;
} rap_reg_request_t;

/**
 * Structure of a /reg response.
 */
typedef struct rap_reg_response_t {
  uint8_t ephemeral_public_key_compressed[1 + ECC_CURVE_P_256_SIZE];
  tiny_dice_cert_chain_t cert_chain;
  uint32_t tee_tci_version;
  uint8_t oscore_ng_mic[COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN];
} rap_reg_response_t;

/**
 * Estimates the maximum payload of a /reg request.
 * @param reg_request      Contents of the /reg request.
 * @return                 Maximum size of the /reg request.
 */
size_t rap_get_reg_requests_payload_size(rap_reg_request_t *reg_request);

/**
 * Writes a /reg request.
 *
 * @param reg_request      Contents of the /reg request.
 * @param payload          CBOR output.
 * @param max_payload_size Maximum number of bytes of the CBOR output.
 *
 * @return                 @c 1 on success, or @c 0 otherwise.
 */
int rap_write_reg_request(rap_reg_request_t *reg_request,
                          uint8_t *payload,
                          size_t max_payload_size);

/**
 * Parses a /reg request.
 *
 * @param reg_request  Contents of the /reg request.
 * @param payload      CBOR input.
 * @param payload_size Number of bytes of the CBOR input.
 *
 * @return             @c 1 on success, or @c 0 otherwise.
 */
int rap_parse_reg_request(rap_reg_request_t *reg_request,
                          const uint8_t *payload,
                          size_t payload_size);

/**
 * Parses a /reg response.
 *
 * @param payload        CBOR input.
 * @param payload_size   Number of bytes of the CBOR input.
 * @param reg_response   Contents of the /reg response.
 *
 * @return               @c 1 on success, or @c 0 otherwise.
 */
int rap_parse_reg_response(const uint8_t *payload,
                           size_t payload_size,
                           rap_reg_response_t *reg_response);

/** @} */

#endif /* OSCORE_NG_RAP_H_ */
