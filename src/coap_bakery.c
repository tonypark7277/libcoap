/*
 * coap_bakery.c -- DoS mitigations
 *
 * Copyright (C) 2021-2023 Uppsala universitet
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_bakery.c
 * @brief DoS mitigations
 */

#include "coap3/coap_internal.h"
#include <stddef.h>
#include <stdint.h>

#if COAP_RAP_SUPPORT && COAP_SERVER_SUPPORT

static int
address_to_bin_const(coap_bin_const_t *bin_const,
                     const coap_address_t *address) {
#ifdef WITH_CONTIKI
  bin_const->s = address->addr.u8;
  bin_const->length = sizeof(address->addr.u8);
#else /* ! WITH_CONTIKI */
  switch (address->addr.sa.sa_family) {
  case AF_INET:
    bin_const->s = (const uint8_t *)&address->addr.sin.sin_addr.s_addr;
    bin_const->length = sizeof(address->addr.sin.sin_addr.s_addr);
    break;
  case AF_INET6:
    bin_const->s = address->addr.sin6.sin6_addr.s6_addr;
    bin_const->length = sizeof(address->addr.sin6.sin6_addr.s6_addr);
    break;
  default:
    return 0;
  }
#endif /* ! WITH_CONTIKI */
  return 1;
}

static void
handle_knock(coap_resource_t *resource,
             coap_session_t *session,
             const coap_pdu_t *request,
             const coap_string_t *query,
             coap_pdu_t *response) {
  (void)resource;
  (void)query;

  /* check padding bytes */
  {
    size_t payload_size;
    const uint8_t *payload;

    if (!coap_get_data(request, &payload_size, &payload)) {
      coap_log_err("handle_knock: coap_get_data failed\n");
      goto error;
    }
    if (payload_size < COAP_BAKERY_COOKIE_SIZE) {
      coap_log_err("handle_knock: insufficient padding bytes\n");
      goto error;
    }
  }

  /* TODO rate limitation */

  /* create response */
  {
    uint8_t *response_payload;
    coap_bin_const_t ip_address;

    response_payload = coap_add_data_after(response, COAP_BAKERY_COOKIE_SIZE);
    if (!response_payload) {
      coap_log_err("handle_knock: coap_add_data_after failed\n");
      goto error;
    }
    if (!address_to_bin_const(&ip_address,
                              coap_session_get_addr_remote(session))) {
      coap_log_err("handle_knock: address_to_bin_const failed\n");
      goto error;
    }
    bakery_bake_cookie(response_payload, &ip_address);
  }
  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
  coap_pdu_set_type(response, COAP_MESSAGE_ACK);
  return;
error:
  /* these two lines cause the ACK to be suppressed */
  coap_pdu_set_code(response, COAP_EMPTY_CODE);
  coap_pdu_set_type(response, COAP_MESSAGE_NON);
}

int
coap_bakery_open(coap_context_t *context) {
  coap_str_const_t *path;
  coap_resource_t *resource;

  path = coap_make_str_const(knock_path);
  resource = coap_resource_init(path, 0);
  if (!resource) {
    coap_log_err("coap_bakery_open: coap_resource_init failed\n");
    return 0;
  }
  coap_register_handler(resource, COAP_REQUEST_GET, handle_knock);
  coap_add_resource(context, resource);
  return 1;
}

int
coap_bakery_check_cookie(const uint8_t cookie[COAP_BAKERY_COOKIE_SIZE],
                         const coap_address_t *address) {
  coap_bin_const_t ip_address;

  if (!address_to_bin_const(&ip_address, address)) {
    coap_log_err("coap_bakery_check_cookie: address_to_bin_const failed\n");
    return 0;
  }
  return bakery_check_cookie(cookie, &ip_address);
}
#else /* ! COAP_RAP_SUPPORT || ! COAP_SERVER_SUPPORT */
int
coap_bakery_open(coap_context_t *context) {
  (void)context;
  return 0;
}

int
coap_bakery_check_cookie(const uint8_t cookie[COAP_BAKERY_COOKIE_SIZE],
                         const coap_address_t *address) {
  (void)cookie;
  (void)address;
  return 0;
}
#endif /* ! COAP_RAP_SUPPORT || ! COAP_SERVER_SUPPORT */
