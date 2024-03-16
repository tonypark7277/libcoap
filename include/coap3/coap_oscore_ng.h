/*
 * coap_oscore_ng.h -- OSCORE-NG support for libcoap
 *
 * Copyright (C) 2021-2023 Uppsala universitet
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_oscore_ng.h
 * @brief OSCORE-NG support for libcoap
 */

#ifndef COAP_OSCORE_NG_H_
#define COAP_OSCORE_NG_H_

/**
 * @ingroup application_api
 * @defgroup oscore_ng OSCORE-NG Support
 * API functions for interfacing with OSCORE-NG
 * @{
 */

typedef struct coap_oscore_ng_keying_material_t {
  coap_bin_const_t master_secret;
  coap_bin_const_t master_salt;
} coap_oscore_ng_keying_material_t;

typedef const coap_oscore_ng_keying_material_t *
(* coap_oscore_ng_keying_material_getter_t)(
    const coap_bin_const_t *recipient_id);

/**
 * Enables OSCORE-NG for a context.
 *
 * @param context                The CoAP context.
 * @param keying_material_getter Returns keying material upon request.
 * @param sender_id              The Sender ID.
 *
 * @return                       @c 1 on success, or @c 0 otherwise.
 */
int coap_oscore_ng_init(
    coap_context_t *context,
    const coap_oscore_ng_keying_material_getter_t keying_material_getter,
    const coap_bin_const_t *sender_id);

/**
 * Enables OSCORE-NG for a client session.
 *
 * @param session      The client session to be protected by OSCORE-NG.
 * @param recipient_id The Recipient ID.
 * @param with_b2      Enables the B2 protocol.
 *
 * @return             @c 1 on success, or @c 0 otherwise.
 */
int coap_oscore_ng_init_client_session(coap_session_t *session,
                                       const coap_bin_const_t *recipient_id,
                                       int with_b2);

/** @} */

#endif /* COAP_OSCORE_NG_H_ */
