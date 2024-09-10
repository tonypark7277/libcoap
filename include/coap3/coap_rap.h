/*
 * coap_rap.h -- remote attestation and key exchange
 *
 * Copyright (C) 2021-2023 Uppsala universitet
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_rap.h
 * @brief remote attestation and key exchange
 */

#ifndef COAP_RAP_H_
#define COAP_RAP_H_

#include "coap3/coap_oscore_ng.h"
#include <stdint.h>
#include <stdlib.h>

/**
 * @ingroup application_api
 * @addtogroup oscore_ng
 * @{
 */

#ifndef WITH_TRAP
#define WITH_TRAP 1
#endif /* WITH_TRAP */

#ifndef COAP_RAP_FHMQV_MIC_SIZE
#define COAP_RAP_FHMQV_MIC_SIZE (8)
#endif /* COAP_RAP_FHMQV_MIC_SIZE */

/**
 * Called when re-entering @c coap_rap is necessary.
 */
typedef void (*coap_rap_resume_t)(void);

/**
 * Matches Contiki-NG's pt.h for seamless integration with protothreads.
 * Other operating systems should act as described.
 */
typedef enum coap_rap_result_t {
  COAP_RAP_RESULT_WAITING = 0, /**< Sleep until callback. */
  COAP_RAP_RESULT_YIELDED = 1, /**< Sleep until callback. */
  COAP_RAP_RESULT_EXITED = 2,  /**< Retry later. */
  COAP_RAP_RESULT_ENDED = 3,   /**< Use session as usual. */
} coap_rap_result_t;

/**
 * Stores established keying material.
 */
typedef int (* coap_rap_keying_material_setter_t)(
    const coap_bin_const_t *recipient_id,
    const uint8_t *secret,
    size_t secret_size);

/**
 * Configures keys, expected hashes, and the OSCORE-NG Recipient ID.
 */
typedef struct coap_rap_config_t {
  coap_rap_resume_t resume;
  const coap_bin_const_t *recipient_id;
  const uint8_t *my_private_key;
#if WITH_TRAP
  const uint8_t *my_public_key;
#endif /* WITH_TRAP */
  const uint8_t *root_of_trusts_public_key;
  const uint8_t *expected_sm_hash;
  const uint8_t *expected_tee_hash;
  coap_rap_keying_material_setter_t keying_material_setter;
} coap_rap_config_t;

#if WITH_TRAP
/**
 * Performs a remote attestation and establishes an OSCORE-NG session.
 * NOTE: For the time being, this functions overwrites response handlers.
 *       Eventually, we should use tokens to dispatch responses and nacks.
 *
 * @param session           The CoAP session to secure.
 * @param config            Defines keys, expected hashes, and the server's ID.
 * @param clients_fhmqv_mic The confirmation MIC to be sent to the server.
 *
 * @return                  Feedback on how to proceed.
 */
#else /* ! WITH_TRAP */
/**
 * Performs a remote attestation and establishes an OSCORE-NG session.
 * NOTE: For the time being, this functions overwrites response handlers.
 *       Eventually, we should use tokens to dispatch responses and nacks.
 *
 * @param session           The CoAP session to secure.
 * @param config            Defines keys, expected hashes, and the server's ID.
 *
 * @return                  Feedback on how to proceed.
 */
#endif /* ! WITH_TRAP */
coap_rap_result_t coap_rap_initiate(
    coap_session_t *session,
    const coap_rap_config_t *config
#if WITH_TRAP
    , uint8_t clients_fhmqv_mic[COAP_RAP_FHMQV_MIC_SIZE]
#endif /* WITH_TRAP */
);

/** @} */

#endif /* COAP_RAP_H_ */
