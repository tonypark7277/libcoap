/*
 * oscore_ng_bakery.h -- DoS mitigations
 *
 * Copyright (C) 2021-2023 Uppsala universitet
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file oscore_ng_bakery.h
 * @brief DoS mitigations
 */

#ifndef OSCORE_NG_BAKERY_H_
#define OSCORE_NG_BAKERY_H_

#include <stddef.h>
#include <stdint.h>

/**
 * @ingroup internal_api
 * @addtogroup oscore_ng_internal
 * @{
 */

#define BAKERY_COOKIE_SIZE (8)

/**
 * Bakes a cookie.
 *
 * @param cookie     Location to put the cookie.
 * @param ip_address Source address.
 *
 * @return           @c 1 on success, or @c 0 otherwise.
 */
int bakery_bake_cookie(uint8_t cookie[BAKERY_COOKIE_SIZE],
                       const coap_bin_const_t *ip_address);

/**
 * Checks the validity of an echoed cookie.
 *
 * @param cookie     The echoed cookie.
 * @param ip_address Source address.
 *
 * @return           @c 1 on success, or @c 0 otherwise.
 */
int bakery_check_cookie(const uint8_t cookie[BAKERY_COOKIE_SIZE],
                        const coap_bin_const_t *ip_address);

/** @} */

#endif /* OSCORE_NG_BAKERY_H_ */
