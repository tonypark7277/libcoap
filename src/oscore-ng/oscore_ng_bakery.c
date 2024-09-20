/*
 * oscore_ng_bakery.c -- DoS mitigations
 *
 * Copyright (C) 2021-2023 Uppsala universitet
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file osocre_ng_bakery.c
 * @brief DoS mitigations
 */

#include "coap3/coap_libcoap_build.h"
#include <stdint.h>
#include <string.h>

#define INTERVAL_DURATION \
  ((OSCORE_NG_ACK_TIMEOUT /* delay from middlebox to client */ \
    + OSCORE_NG_PROCESSING_DELAY /* turnaround time */ \
    + OSCORE_NG_MAX_TRANSMIT_SPAN /* potential retransmissions */ \
    + OSCORE_NG_ACK_TIMEOUT /* delay from client to middlebox */) \
   * 10 /* from centiseconds to milliseconds */)

static uint64_t current_interval_start;
static uint8_t current_key[AES_128_KEY_LENGTH];
static uint_fast8_t current_interval;
static int has_previous_key;
static uint8_t previous_key[AES_128_KEY_LENGTH];

static int
update_cookie_key(void) {
  uint64_t now;
  uint32_t passed_intervals;

  now = oscore_ng_generate_timestamp();
  if (!now) {
    return 0;
  }

  /* lazy initialization */
  if (!current_interval_start) {
    if (!oscore_ng_csprng(current_key, sizeof(current_key))) {
      return 0;
    }
    current_interval_start = now;
  }

  passed_intervals = (now - current_interval_start) / INTERVAL_DURATION;
  if (!passed_intervals) {
    return 1;
  }

  if (passed_intervals == 1) {
    has_previous_key = 1;
    memcpy(previous_key, current_key, sizeof(previous_key));
  } else {
    has_previous_key = 0;
  }

  if (!oscore_ng_csprng(current_key, sizeof(current_key))) {
    return 0;
  }
  current_interval += passed_intervals;
  current_interval_start += INTERVAL_DURATION * passed_intervals;
  return 1;
}

static int
bake_specific_cookie(uint8_t cookie[BAKERY_COOKIE_SIZE],
                     const coap_bin_const_t *ip_address,
                     uint8_t key[AES_128_KEY_LENGTH],
                     uint_fast8_t interval) {
  uint8_t hmac[SHA_256_DIGEST_LENGTH];

  sha_256_hmac(key,
               AES_128_KEY_LENGTH,
               ip_address->s,
               ip_address->length,
               hmac);
  memcpy(cookie, hmac, BAKERY_COOKIE_SIZE);
  /* last bit indicates interval */
  cookie[BAKERY_COOKIE_SIZE - 1] &= ~1;
  cookie[BAKERY_COOKIE_SIZE - 1] |= interval & 1;
  return 1;
}

int
bakery_bake_cookie(uint8_t cookie[BAKERY_COOKIE_SIZE],
                   const coap_bin_const_t *ip_address) {
  if (!update_cookie_key()) {
    return 0;
  }
  return bake_specific_cookie(cookie,
                              ip_address,
                              current_key,
                              current_interval);
}

int
bakery_check_cookie(const uint8_t cookie[BAKERY_COOKIE_SIZE],
                    const coap_bin_const_t *ip_address) {
  int is_recent_cookie;

  if (!update_cookie_key()) {
    return 0;
  }
  is_recent_cookie = (cookie[BAKERY_COOKIE_SIZE - 1] & 1)
                     == (current_interval & 1);
  if (!is_recent_cookie && !has_previous_key) {
    return 0;
  }

  {
    uint8_t expected_cookie[BAKERY_COOKIE_SIZE];

    bake_specific_cookie(expected_cookie,
                         ip_address,
                         is_recent_cookie
                         ? current_key
                         : previous_key,
                         is_recent_cookie
                         ? current_interval
                         : current_interval - 1);
    return !memcmp(expected_cookie, cookie, BAKERY_COOKIE_SIZE);
  }
}
