/*
 * coap_bakery.h -- DoS mitigations
 *
 * Copyright (C) 2021-2023 Uppsala universitet
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_bakery.h
 * @brief DoS mitigations
 */

#ifndef COAP_BAKERY_H_
#define COAP_BAKERY_H_

#include "coap3/coap_oscore_ng.h"
#include <stdint.h>

/**
 * @ingroup application_api
 * @addtogroup oscore_ng
 * @{
 */

#define COAP_BAKERY_COOKIE_SIZE (8)

/**
 * Once opened, the bakery serves /kno requests.
 *
 * @param context The CoAP context.
 *
 * @return        @c 1 on success, or @c 0 otherwise.
 */
int coap_bakery_open(coap_context_t *context);

/**
 * Checks the validity of an echoed cookie.
 *
 * @param cookie  The echoed cookie.
 * @param address Source address.
 *
 * @return        @c 1 on success, or @c 0 otherwise.
 */
int coap_bakery_check_cookie(const uint8_t cookie[COAP_BAKERY_COOKIE_SIZE],
                             const coap_address_t *address);

/** @} */

#endif /* COAP_BAKERY_H_ */
