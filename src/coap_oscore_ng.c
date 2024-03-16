/*
 * coap_oscore_ng.c -- OSCORE-NG support for libcoap
 *
 * Copyright (C) 2021-2023 Uppsala universitet
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_oscore_ng.c
 * @brief OSCORE-NG support for libcoap
 */

#include "coap3/coap_libcoap_build.h"
#include <stdio.h>
#include <stdint.h>
#ifdef __linux__
#include <time.h>
#endif /* __linux__ */

#if COAP_OSCORE_NG_SUPPORT

#define PAYLOAD_MARKER_LEN (1)
uint64_t
oscore_ng_generate_timestamp(void) {
#if defined(WITH_CONTIKI) || defined(WITH_LWIP)
  coap_tick_t now;
  coap_ticks(&now);
  return ((uint64_t)now * 100 / COAP_TICKS_PER_SECOND) + 1;
#elif defined(__linux__)
  uint64_t centiseconds;
  struct timespec tv;
  if (clock_gettime(CLOCK_BOOTTIME, &tv)) {
    return 0;
  }
  centiseconds = tv.tv_sec * 100;
  centiseconds += tv.tv_nsec / 10000000;
  return centiseconds + 1;
#else /* ! WITH_CONTIKI && ! WITH_LWIP && ! __linux__*/
  /* TODO implement a clock without discontinuous jumps for other platforms */
  return 0;
#endif /* ! WITH_CONTIKI && ! WITH_LWIP && ! __linux__ */
}

int
oscore_ng_csprng(void *dst, size_t dst_len) {
  return coap_prng_lkd(dst, dst_len);
}

oscore_ng_anti_replay_t *
oscore_ng_alloc_anti_replay(void) {
  return coap_malloc_type(COAP_OSCORE_NG_ANTI_REPLAY,
                          sizeof(oscore_ng_anti_replay_t));
}

void
oscore_ng_free_anti_replay(oscore_ng_anti_replay_t *anti_replay) {
  coap_free_type(COAP_OSCORE_NG_ANTI_REPLAY, anti_replay);
}

static int
bin_const_to_oscore_ng_id(oscore_ng_id_t *oscore_ng_id,
                          const coap_bin_const_t *bin_const) {
  if (bin_const->length > OSCORE_NG_MAX_ID_LEN) {
    return 0;
  }
  oscore_ng_id->len = bin_const->length;
  memcpy(oscore_ng_id->u8, bin_const->s, bin_const->length);
  return 1;
}

int
coap_oscore_ng_init(
    coap_context_t *context,
    const coap_oscore_ng_keying_material_getter_t keying_material_getter,
    const coap_bin_const_t *sender_id) {
  if (context->oscore_ng) {
    coap_log_err("coap_oscore_ng_init: already initialized\n");
    return 0;
  }
  context->oscore_ng = coap_malloc_type(COAP_OSCORE_NG_GENERAL_CONTEXT,
                                        sizeof(*context->oscore_ng));
  if (!context->oscore_ng) {
    coap_log_err("coap_oscore_ng_init: coap_malloc_type failed\n");
    return 0;
  }
  context->oscore_ng->keying_material_getter = keying_material_getter;
  if (!bin_const_to_oscore_ng_id(&context->oscore_ng->sender_id,
                                 sender_id)) {
    coap_free_type(COAP_OSCORE_NG_GENERAL_CONTEXT, context->oscore_ng);
    context->oscore_ng = NULL;
    coap_log_err("coap_oscore_ng_init: bin_const_to_oscore_ng_id failed\n");
  }
  return 1;
}

int
coap_oscore_ng_init_session(coap_session_t *session,
                            const oscore_ng_id_t *recipient_id) {
  coap_oscore_ng_general_context_t *general_context =
      session->context->oscore_ng;
  coap_bin_const_t converted_recipient_id = {
    converted_recipient_id.length = recipient_id->len,
    converted_recipient_id.s = recipient_id->u8
  };
  const oscore_ng_keying_material_t *keying_material =
      general_context->keying_material_getter(&converted_recipient_id);
  if (!keying_material) {
    coap_log_err("coap_oscore_ng_init_session: "
                 "keying_material_getter failed\n");
    return 0;
  }
  session->oscore_ng_context = coap_malloc_type(
                                   COAP_OSCORE_NG_CONTEXT,
                                   sizeof(*session->oscore_ng_context));
  if (!session->oscore_ng_context) {
    coap_log_err("coap_oscore_ng_init_session: coap_malloc_type failed\n");
    return 0;
  }
  if (!oscore_ng_init_context(session->oscore_ng_context,
                              recipient_id,
                              &general_context->sender_id,
                              keying_material)) {
    coap_log_err("coap_oscore_ng_init_session: oscore_ng_init_context failed\n");
    return 0;
  }
  return 1;
}

void
coap_oscore_ng_clear_context(oscore_ng_context_t *context) {
  if (!context) {
    return;
  }
  oscore_ng_clear_context(context);
  coap_free_type(COAP_OSCORE_NG_CONTEXT, context);
}

#if COAP_CLIENT_SUPPORT
int
coap_oscore_ng_init_client_session(coap_session_t *session,
                                   const coap_bin_const_t *recipient_id,
                                   int with_b2) {
  if (!session->context->oscore_ng) {
    coap_log_err("coap_oscore_ng_init_client_session: "
                 "coap_oscore_ng_init must be called first\n");
    return 0;
  }
  oscore_ng_id_t converted_recipient_id;
  if (!bin_const_to_oscore_ng_id(&converted_recipient_id, recipient_id)) {
    coap_log_err("coap_oscore_ng_init_client_session: "
                 "bin_const_to_oscore_ng_id failed\n");
    return 0;
  }
  if (!coap_oscore_ng_init_session(session, &converted_recipient_id)) {
    coap_log_err("coap_oscore_ng_init_client_session: "
                 "coap_oscore_ng_init_session failed\n");
    return 0;
  }
  if (with_b2) {
    oscore_ng_start_b2(session->oscore_ng_context);
  }
  return 1;
}
#endif /* COAP_CLIENT_SUPPORT */

static void
init_outer_option_filter(coap_opt_filter_t *outer_opt_filter) {
  coap_option_filter_clear(outer_opt_filter);
  coap_option_filter_set(outer_opt_filter, COAP_OPTION_URI_HOST);
  coap_option_filter_set(outer_opt_filter, COAP_OPTION_URI_PORT);
  coap_option_filter_set(outer_opt_filter, COAP_OPTION_PROXY_SCHEME);
  coap_option_filter_set(outer_opt_filter, COAP_OPTION_HOP_LIMIT);
}

static coap_pdu_t *
shadow_pdu(coap_pdu_t *pdu, size_t size) {
  coap_pdu_t *new_pdu;
  coap_bin_const_t token;

  new_pdu = coap_pdu_init(pdu->type, pdu->code, pdu->mid, size);
  if (!new_pdu) {
    return NULL;
  }
  token = coap_pdu_get_token(pdu);
  if (!coap_add_token(new_pdu, token.length, token.s)) {
    coap_delete_pdu_lkd(new_pdu);
    return NULL;
  }
  return new_pdu;
}

coap_pdu_t *
coap_oscore_ng_message_encrypt(coap_session_t *session, coap_pdu_t *pdu) {
  int is_request = COAP_PDU_IS_REQUEST(pdu) || COAP_PDU_IS_PING(pdu);
  coap_pdu_t *inner_pdu;
  coap_opt_filter_t outer_opt_filter;
  oscore_ng_option_value_t oscore_ng_option_value;

  coap_lock_check_locked();

  if (!session->oscore_ng_context /* OSCORE-NG disabled */) {
    return pdu;
  }

  /* construct inner PDU */
  {
    size_t payload_length;
    size_t inner_pdu_size;
    coap_opt_iterator_t oi;
    uint16_t max_opt;
    coap_opt_t *option;
    uint8_t original_code;

    /* compute size of inner pdu */
    inner_pdu_size = 1; /* 1-byte pseudo-token contains the actual code */
    if (pdu->data) {
      payload_length = pdu->used_size - (pdu->data - pdu->token);
      inner_pdu_size += PAYLOAD_MARKER_LEN;
      inner_pdu_size += payload_length;
    } else {
      payload_length = 0;
    }
    inner_pdu_size += COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN;
    init_outer_option_filter(&outer_opt_filter);
    coap_option_iterator_init(pdu, &oi, COAP_OPT_ALL);
    max_opt = 0;
    while ((option = coap_option_next(&oi))) {
      if (!coap_option_filter_get(&outer_opt_filter, oi.number)) {
        inner_pdu_size += coap_opt_encode_size(oi.number - max_opt,
                                               coap_opt_length(option));
        max_opt = oi.number;
      }
    }

    /* create PDU of computed size */
    inner_pdu = coap_pdu_init(pdu->type, pdu->code, pdu->mid, inner_pdu_size);
    if (!inner_pdu) {
      coap_log_err("coap_oscore_ng_message_encrypt: coap_pdu_init failed\n");
      return NULL;
    }

    /* add pseudo-token for the original code */
    original_code = pdu->code;
    if (!coap_add_token(inner_pdu, sizeof(original_code), &original_code)) {
      coap_log_err("coap_oscore_ng_message_encrypt: coap_add_token failed\n");
      return NULL;
    }

    /* add inner options */
    coap_option_iterator_init(pdu, &oi, COAP_OPT_ALL);
    while ((option = coap_option_next(&oi))) {
      if (!coap_option_filter_get(&outer_opt_filter, oi.number)
          && !coap_add_option(inner_pdu,
                              oi.number,
                              coap_opt_length(option),
                              coap_opt_value(option))) {
        coap_log_err("coap_oscore_ng_message_encrypt: "
                     "Adding inner option failed\n");
        goto error_1;
      }
    }

    /* add payload */
    if (!coap_add_data(inner_pdu, payload_length, pdu->data)) {
      coap_log_err("coap_oscore_ng_message_encrypt: Copying payload failed\n");
      goto error_1;
    }
  }

  /* secure and create OSCORE-NG option */
  {
    int secure_result;
    oscore_ng_option_data_t oscore_ng_option_data;

    secure_result = oscore_ng_secure(session->oscore_ng_context,
                                     pdu->type,
                                     &pdu->actual_token,
                                     &oscore_ng_option_data,
                                     pdu->mid,
                                     inner_pdu->token, inner_pdu->used_size,
                                     is_request);
    if (!secure_result) {
      coap_log_err("coap_oscore_ng_message_encrypt: "
                   "oscore_ng_secure failed\n");
      goto error_1;
    }
    inner_pdu->used_size += COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN;
    oscore_ng_encode_option(&oscore_ng_option_value,
                            &oscore_ng_option_data,
                            is_request);
  }

  /* construct outer PDU */
  {
    size_t outer_pdu_size;
    coap_opt_iterator_t oi;
    int added_oscore_ng_option;
    uint16_t max_opt;
    coap_opt_t *option;
    coap_pdu_t *outer_pdu;

    /* compute size of outer PDU size */
    outer_pdu_size = PAYLOAD_MARKER_LEN;
    outer_pdu_size += pdu->actual_token.length;
    if (pdu->actual_token.length >= COAP_TOKEN_EXT_1B_BIAS) {
      outer_pdu_size++;
      if (pdu->actual_token.length >= COAP_TOKEN_EXT_2B_BIAS) {
        outer_pdu_size++;
      }
    }
    coap_option_iterator_init(pdu, &oi, &outer_opt_filter);
    added_oscore_ng_option = 0;
    max_opt = 0;
    while (1) {
      option = coap_option_next(&oi);
      if ((!option || (oi.number > COAP_OPTION_OSCORE))
          && !added_oscore_ng_option) {
        outer_pdu_size += coap_opt_encode_size(COAP_OPTION_OSCORE - max_opt,
                                               oscore_ng_option_value.len);
        max_opt = COAP_OPTION_OSCORE;
        added_oscore_ng_option = 1;
      }
      if (!option) {
        break;
      }
      outer_pdu_size += coap_opt_encode_size(oi.number - max_opt,
                                             coap_opt_length(option));
      max_opt = oi.number;
    }
    outer_pdu_size += inner_pdu->used_size;

    /* create PDU of computed size */
    outer_pdu = shadow_pdu(pdu, outer_pdu_size);
    if (!outer_pdu) {
      coap_log_err("create_outer_pdu: shadow_pdu failed\n");
      goto error_1;
    }

    /* add outer options */
    coap_option_iterator_init(pdu, &oi, &outer_opt_filter);
    added_oscore_ng_option = 0;
    while (1) {
      option = coap_option_next(&oi);
      if ((!option || (oi.number > COAP_OPTION_OSCORE))
          && !added_oscore_ng_option) {
        if (!coap_add_option(outer_pdu,
                             COAP_OPTION_OSCORE,
                             oscore_ng_option_value.len,
                             oscore_ng_option_value.u8)) {
          coap_log_err("create_outer_pdu: Adding OSCORE-NG option failed\n");
          goto error_2;
        }
        added_oscore_ng_option = 1;
      }
      if (!option) {
        break;
      }
      if (!coap_add_option(outer_pdu,
                           oi.number,
                           coap_opt_length(option),
                           coap_opt_value(option))) {
        coap_log_err("coap_oscore_ng_message_encrypt: "
                     "Adding outer option failed\n");
        goto error_2;
      }
    }

    /* add ciphertext */
    if (!coap_add_data(outer_pdu, inner_pdu->used_size, inner_pdu->token)) {
      coap_log_err("coap_oscore_ng_message_encrypt: coap_add_data failed\n");
      goto error_2;
    }

    /* mask CoAP code */
    coap_pdu_set_code(outer_pdu,
                      is_request
                      ? COAP_REQUEST_CODE_POST
                      : COAP_RESPONSE_CODE_CHANGED);
    if (!coap_pdu_encode_header(outer_pdu, session->proto)) {
      coap_log_err("coap_oscore_ng_message_encrypt: Masking code failed\n");
      goto error_2;
    }

    coap_delete_pdu_lkd(inner_pdu);
    return outer_pdu;
error_2:
    coap_delete_pdu_lkd(outer_pdu);
  }
error_1:
  coap_delete_pdu_lkd(inner_pdu);
  return NULL;
}

coap_pdu_t *
coap_oscore_ng_message_decrypt(coap_session_t *session,
                               coap_pdu_t *pdu,
                               int *is_b2_request_1) {
  *is_b2_request_1 = 0;
#if COAP_SERVER_SUPPORT
  int has_created_session = 0;
#endif /* COAP_SERVER_SUPPORT */
  int is_request = COAP_PDU_IS_REQUEST(pdu);
  oscore_ng_option_data_t oscore_ng_option_data;

  coap_lock_check_locked();

  /* inspect options */
  {
    coap_opt_iterator_t oi;

    if (coap_check_option(pdu, COAP_OPTION_PROXY_URI, &oi)
        || coap_check_option(pdu, COAP_OPTION_PROXY_SCHEME, &oi)) {
      coap_log_debug("coap_oscore_ng_message_decrypt: "
                     "Message with a Proxy-* Option\n");
      return pdu;
    }
  }
  if (!session->oscore_ng_context
#if COAP_SERVER_SUPPORT
      && ((session->type != COAP_SESSION_TYPE_SERVER)
          || !session->context->oscore_ng)
#endif /* COAP_SERVER_SUPPORT */
     ) {
    /* not an OSCORE-NG session */
    return pdu;
  }
  if (!coap_oscore_ng_parse_option(&oscore_ng_option_data, pdu, is_request)) {
    if (is_request && !session->oscore_ng_context) {
      /* will later be dropped if COAP_RESOURCE_FLAGS_OSCORE_NG_ONLY */
      return pdu;
    }
    coap_log_debug("coap_oscore_ng_message_decrypt: "
                   "coap_oscore_ng_parse_option failed\n");
    return NULL;
  }

#if COAP_SERVER_SUPPORT
  /* create session if necessary */
  if (!session->oscore_ng_context) {
    if (!coap_oscore_ng_init_session(session, &oscore_ng_option_data.kid)) {
      coap_log_err("coap_oscore_ng_message_decrypt: "
                   "coap_oscore_ng_init_session failed\n");
      return NULL;
    }
    has_created_session = 1;
  }
#endif /* COAP_SERVER_SUPPORT */

  /* decrypt */
  {
    uint8_t *ciphertext;
    size_t ciphertext_len;
    coap_pdu_t *original_pdu;
    coap_opt_filter_t outer_opt_filter;
    coap_opt_iterator_t outer_oi;
    coap_opt_iterator_t inner_oi;
    coap_opt_t *outer_option;
    coap_opt_t *inner_option;

    /* AEAD */
    ciphertext = pdu->data;
    if (!ciphertext) {
      coap_log_err("coap_oscore_ng_message_decrypt: Ciphertext is NULL\n");
      goto error_1;
    }
    ciphertext_len = pdu->used_size - (pdu->data - pdu->token);
    switch (oscore_ng_unsecure(session->oscore_ng_context,
                               pdu->type,
                               &pdu->actual_token,
                               &oscore_ng_option_data,
                               ciphertext, ciphertext_len,
                               is_request,
                               0)) {
    case OSCORE_NG_UNSECURE_RESULT_B2_REQUEST_1:
      *is_b2_request_1 = 1;
      /* complete B2 first */
      return NULL;
    case OSCORE_NG_UNSECURE_RESULT_DUPLICATE:
      coap_log_warn("coap_oscore_ng_message_decrypt: Received duplicate\n");
      if (!is_request) {
        goto error_1;
      }
      /* TODO cache responses to non-idempotent requests */
      break;
    case OSCORE_NG_UNSECURE_RESULT_OK:
      break;
    case OSCORE_NG_UNSECURE_RESULT_ERROR:
    default:
      coap_log_warn("coap_oscore_ng_message_decrypt: "
                    "Inauthentic OSCORE-NG message\n");
      goto error_1;
    }
    ciphertext_len -= COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN;

    /* create original_pdu */
    original_pdu =
        shadow_pdu(
            pdu,
            pdu->used_size - COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN);
    if (!original_pdu) {
      coap_log_err("coap_oscore_ng_message_decrypt: shadow_pdu failed\n");
      goto error_1;
    }

    /* restore code */
    if (!ciphertext_len) {
      coap_log_err("coap_oscore_ng_message_decrypt: Empty plaintext\n");
      goto error_2;
    }
    coap_pdu_set_code(original_pdu, *ciphertext);
    ciphertext++;
    ciphertext_len--;

    /* init option iterators */
    init_outer_option_filter(&outer_opt_filter);
    coap_option_iterator_init(pdu, &outer_oi, &outer_opt_filter);
    memset(&inner_oi, 0, sizeof(inner_oi));
    inner_oi.next_option = ciphertext;
    if (!ciphertext_len) {
      inner_oi.bad = 1;
    } else {
      inner_oi.length = ciphertext_len;
    }

    /* copy unprotected and protected options to original_pdu */
    outer_option = coap_option_next(&outer_oi);
    inner_option = coap_option_next(&inner_oi);
    while (outer_option || inner_option) {
      if (outer_option
          && (!inner_option || (outer_oi.number < inner_oi.number))) {
        if (!coap_add_option(original_pdu,
                             outer_oi.number,
                             coap_opt_length(outer_option),
                             coap_opt_value(outer_option))) {
          coap_log_err("coap_oscore_ng_message_decrypt: "
                       "coap_add_option failed\n");
          goto error_2;
        }
        outer_option = coap_option_next(&outer_oi);
      } else if (inner_option) {
        if (!coap_add_option(original_pdu,
                             inner_oi.number,
                             coap_opt_length(inner_option),
                             coap_opt_value(inner_option))) {
          coap_log_err("coap_oscore_ng_message_decrypt: "
                       "coap_add_option failed\n");
          goto error_2;
        }
        inner_option = coap_option_next(&inner_oi);
      }
    }

    /* copy payload to original_pdu */
    if (inner_oi.length && (*inner_oi.next_option == COAP_PAYLOAD_START)) {
      if (!coap_add_data(original_pdu,
                         inner_oi.length - 1,
                         inner_oi.next_option + 1)) {
        coap_log_err("coap_oscore_ng_message_decrypt: "
                     "coap_add_data failed\n");
        goto error_2;
      }
    }
    return original_pdu;
error_2:
    coap_delete_pdu_lkd(original_pdu);
  }
error_1:
#if COAP_SERVER_SUPPORT
  if (has_created_session) {
    coap_oscore_ng_clear_context(session->oscore_ng_context);
    session->oscore_ng_context = NULL;
  }
#endif /* COAP_SERVER_SUPPORT */
  return NULL;
}

int
coap_oscore_ng_parse_option(oscore_ng_option_data_t *option_data,
                            const coap_pdu_t *pdu,
                            int is_request) {
  coap_opt_iterator_t oi;
  coap_opt_t *oscore_ng_option;

  oscore_ng_option = coap_check_option(pdu, COAP_OPTION_OSCORE, &oi);
  if (!oscore_ng_option) {
    coap_log_warn("coap_oscore_ng_parse_option: coap_check_option failed\n");
    return 0;
  }
  if (!oscore_ng_decode_option(option_data,
                               coap_pdu_get_mid(pdu),
                               is_request,
                               coap_opt_value(oscore_ng_option),
                               coap_opt_length(oscore_ng_option))) {
    coap_log_err("coap_oscore_ng_parse_option: "
                 "oscore_ng_decode_option failed\n");
    return 0;
  }
  return 1;
}
#else /* ! COAP_OSCORE_NG_SUPPORT */
int
coap_oscore_ng_init(
    coap_context_t *context,
    const coap_oscore_ng_keying_material_getter_t keying_material_getter,
    const coap_bin_const_t *sender_id) {
  (void)context;
  (void)keying_material_getter;
  (void)sender_id;
  return 0;
}

int
coap_oscore_ng_init_client_session(coap_session_t *session,
                                   const coap_bin_const_t *recipient_id,
                                   int with_b2) {
  (void)session;
  (void)recipient_id;
  (void)with_b2;
  return 0;
}
#endif /* ! COAP_OSCORE_NG_SUPPORT */
