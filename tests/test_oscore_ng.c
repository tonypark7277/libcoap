/* libcoap unit tests
 *
 * Copyright (C) 2023 Uppsala universitet
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "test_common.h"

#if COAP_OSCORE_NG_SUPPORT
#include "test_oscore_ng.h"
#include "oscore-ng/oscore_ng.h"

#include <string.h>
#include <unistd.h>

static const uint8_t master_secret[] = {
  0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
  0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF
};
static const oscore_ng_id_t id_a = {{ 0xA },1};
static const oscore_ng_id_t id_b = {{ 0xB },1};
static const uint8_t data[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
static const uint8_t token_bytes[] = { 1, 2, 3 };
static const coap_bin_const_t token = {
  sizeof(token_bytes), token_bytes
};
static const coap_bin_const_t empty_token = {
  0, NULL
};

static const coap_oscore_ng_keying_material_t keying_material = {
  { sizeof(master_secret), master_secret }, { 0, NULL }
};

/************************************************************************
 ** tests
 ************************************************************************/

static void
t_oscore_ng_self(void) {
  CU_ASSERT(oscore_ng_self_test());
}

static void
t_oscore_ng_secure_unsecure(void) {
  oscore_ng_context_t context_a;
  oscore_ng_context_t context_b;
  uint8_t request[sizeof(data) + COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN];
  uint16_t message_id = 123;
  bool is_request = true;
  oscore_ng_option_data_t option_data;
  oscore_ng_option_value_t option_value;

  CU_ASSERT(oscore_ng_init_context(&context_a, &id_b, &id_a, &keying_material));
  CU_ASSERT(oscore_ng_init_context(&context_b, &id_a, &id_b, &keying_material));
  memcpy(request, data, sizeof(data));
  CU_ASSERT(oscore_ng_secure(&context_a,
                             COAP_MESSAGE_CON,
                             &token,
                             &option_data,
                             message_id,
                             request, sizeof(data),
                             is_request));
  CU_ASSERT(option_data.e2e_message_id == message_id);
  oscore_ng_encode_option(&option_value, &option_data, is_request);
  CU_ASSERT(oscore_ng_decode_option(&option_data,
                                    message_id,
                                    is_request,
                                    option_value.u8,
                                    option_value.len));
  CU_ASSERT(oscore_ng_unsecure(&context_b,
                               COAP_MESSAGE_CON,
                               &token,
                               &option_data,
                               request, sizeof(request),
                               is_request,
                               0) == OSCORE_NG_UNSECURE_RESULT_OK);
  CU_ASSERT(!memcmp(request, data, sizeof(data)));
}

static void
t_oscore_ng_sps_sanity_check(void) {
  oscore_ng_context_t context_a;
  oscore_ng_context_t context_b;
  uint8_t request[sizeof(data) + COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN];
  uint16_t message_id = 123;
  bool is_request = true;
  oscore_ng_option_data_t option_data;
  oscore_ng_option_value_t option_value;

  CU_ASSERT(oscore_ng_init_context(&context_a, &id_b, &id_a, &keying_material));
  CU_ASSERT(oscore_ng_init_context(&context_b, &id_a, &id_b, &keying_material));

  /* send request like in the previous test */
  memcpy(request, data, sizeof(data));
  CU_ASSERT(oscore_ng_secure(&context_a,
                             COAP_MESSAGE_CON,
                             &empty_token,
                             &option_data,
                             message_id,
                             request, sizeof(data),
                             is_request));
  CU_ASSERT(option_data.e2e_message_id == message_id);
  oscore_ng_encode_option(&option_value, &option_data, is_request);
  CU_ASSERT(oscore_ng_decode_option(&option_data,
                                    message_id,
                                    is_request,
                                    option_value.u8,
                                    option_value.len));
  CU_ASSERT(oscore_ng_unsecure(&context_b,
                               COAP_MESSAGE_CON,
                               &empty_token,
                               &option_data,
                               request, sizeof(request),
                               is_request,
                               0) == OSCORE_NG_UNSECURE_RESULT_OK);

  /* echo request with a simulated delay */
  is_request = false;
  CU_ASSERT(oscore_ng_secure(&context_b,
                             COAP_MESSAGE_ACK,
                             &empty_token,
                             &option_data,
                             message_id,
                             request, sizeof(data),
                             is_request));
  oscore_ng_encode_option(&option_value, &option_data, is_request);
  CU_ASSERT(oscore_ng_decode_option(&option_data,
                                    message_id,
                                    is_request,
                                    option_value.u8,
                                    option_value.len));
  sleep(5);
  CU_ASSERT(oscore_ng_unsecure(&context_a,
                               COAP_MESSAGE_ACK,
                               &empty_token,
                               &option_data,
                               request, sizeof(request),
                               is_request,
                               0) == OSCORE_NG_UNSECURE_RESULT_ERROR);
  oscore_ng_clear_context(&context_a);
  CU_ASSERT(!list_head(context_a.anti_replay_list));
  oscore_ng_clear_context(&context_b);
  CU_ASSERT(!list_head(context_b.anti_replay_list));
}

static void
t_oscore_ng_strong_freshness(void) {
  oscore_ng_context_t context_a;
  oscore_ng_context_t context_b;
  uint8_t request[sizeof(data) + COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN];
  uint16_t message_id = 123;
  bool is_request = true;
  oscore_ng_option_data_t option_data;
  oscore_ng_option_value_t option_value;

  CU_ASSERT(oscore_ng_init_context(&context_a, &id_b, &id_a, &keying_material));
  CU_ASSERT(oscore_ng_init_context(&context_b, &id_a, &id_b, &keying_material));

  /* send and respond to two requests so that SPS is done */
  for (uint_fast8_t i = 0; i < 2; i++) {
    is_request = true;
    message_id++;
    memcpy(request, data, sizeof(data));
    CU_ASSERT(oscore_ng_secure(&context_a,
                               COAP_MESSAGE_CON,
                               &empty_token,
                               &option_data,
                               message_id,
                               request, sizeof(data),
                               is_request));
    CU_ASSERT(option_data.e2e_message_id == message_id);
    oscore_ng_encode_option(&option_value, &option_data, is_request);
    sleep(1);
    CU_ASSERT(oscore_ng_decode_option(&option_data,
                                      message_id,
                                      is_request,
                                      option_value.u8,
                                      option_value.len));
    CU_ASSERT(oscore_ng_unsecure(&context_b,
                                 COAP_MESSAGE_CON,
                                 &empty_token,
                                 &option_data,
                                 request, sizeof(request),
                                 is_request,
                                 0) == OSCORE_NG_UNSECURE_RESULT_OK);

    /* echo request */
    is_request = false;
    CU_ASSERT(oscore_ng_secure(&context_b,
                               COAP_MESSAGE_ACK,
                               &empty_token,
                               &option_data,
                               message_id,
                               request, sizeof(data),
                               is_request));
    oscore_ng_encode_option(&option_value, &option_data, is_request);
    sleep(1);
    CU_ASSERT(oscore_ng_decode_option(&option_data,
                                      message_id,
                                      is_request,
                                      option_value.u8,
                                      option_value.len));
    CU_ASSERT(oscore_ng_unsecure(&context_a,
                                 COAP_MESSAGE_ACK,
                                 &empty_token,
                                 &option_data,
                                 request, sizeof(request),
                                 is_request,
                                 0) == OSCORE_NG_UNSECURE_RESULT_OK);
  }

  /* now send a request with a delay */
  is_request = true;
  message_id++;
  memcpy(request, data, sizeof(data));
  CU_ASSERT(oscore_ng_secure(&context_a,
                             COAP_MESSAGE_CON,
                             &empty_token,
                             &option_data,
                             message_id,
                             request, sizeof(data),
                             is_request));
  CU_ASSERT(option_data.e2e_message_id == message_id);
  oscore_ng_encode_option(&option_value, &option_data, is_request);
  CU_ASSERT(oscore_ng_decode_option(&option_data,
                                    message_id,
                                    is_request,
                                    option_value.u8,
                                    option_value.len));
  sleep(8);
  CU_ASSERT(!oscore_ng_unsecure(&context_b,
                                COAP_MESSAGE_CON,
                                &empty_token,
                                &option_data,
                                request, sizeof(request),
                                is_request,
                                0));
  oscore_ng_clear_context(&context_a);
  CU_ASSERT(!list_head(context_a.anti_replay_list));
  oscore_ng_clear_context(&context_b);
  CU_ASSERT(!list_head(context_b.anti_replay_list));
}

static void
t_oscore_ng_b2(void) {
  oscore_ng_context_t context_a;
  oscore_ng_context_t context_b;
  uint8_t request[sizeof(data) + COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN];
  uint16_t message_id = 123;
  bool is_request = true;
  oscore_ng_option_data_t option_data;
  oscore_ng_option_value_t option_value;

  CU_ASSERT(oscore_ng_init_context(&context_a, &id_b, &id_a, &keying_material));
  CU_ASSERT(oscore_ng_init_context(&context_b, &id_a, &id_b, &keying_material));
  oscore_ng_start_b2(&context_a);

  /* Request #1 */
  memcpy(request, data, sizeof(data));
  CU_ASSERT(oscore_ng_secure(&context_a,
                             COAP_MESSAGE_NON,
                             &empty_token,
                             &option_data,
                             message_id,
                             request, sizeof(data),
                             is_request));
  CU_ASSERT(option_data.e2e_message_id == message_id);
  CU_ASSERT(option_data.kid_context.len);
  oscore_ng_encode_option(&option_value, &option_data, is_request);
  CU_ASSERT(oscore_ng_decode_option(&option_data,
                                    message_id,
                                    is_request,
                                    option_value.u8,
                                    option_value.len));
  CU_ASSERT(oscore_ng_unsecure(&context_b,
                               COAP_MESSAGE_NON,
                               &empty_token,
                               &option_data,
                               request,
                               sizeof(request),
                               is_request,
                               0
                              ) == OSCORE_NG_UNSECURE_RESULT_B2_REQUEST_1);

  /* Response #1 */
  is_request = false;
  CU_ASSERT(oscore_ng_secure(&context_b,
                             COAP_MESSAGE_RST,
                             &empty_token,
                             &option_data,
                             message_id,
                             request, sizeof(data),
                             is_request));
  oscore_ng_encode_option(&option_value, &option_data, is_request);
  CU_ASSERT(option_data.kid_context.len);
  CU_ASSERT(oscore_ng_decode_option(&option_data,
                                    message_id,
                                    is_request,
                                    option_value.u8,
                                    option_value.len));
  CU_ASSERT(oscore_ng_unsecure(&context_a,
                               COAP_MESSAGE_RST,
                               &empty_token,
                               &option_data,
                               request, sizeof(request),
                               is_request,
                               0) == OSCORE_NG_UNSECURE_RESULT_OK);

  /* Request #2 */
  is_request = true;
  message_id++;
  memcpy(request, data, sizeof(data));
  CU_ASSERT(oscore_ng_secure(&context_a,
                             COAP_MESSAGE_NON,
                             &empty_token,
                             &option_data,
                             message_id,
                             request, sizeof(data),
                             is_request));
  CU_ASSERT(option_data.e2e_message_id == message_id);
  CU_ASSERT(option_data.kid_context.len);
  oscore_ng_encode_option(&option_value, &option_data, is_request);
  CU_ASSERT(oscore_ng_decode_option(&option_data,
                                    message_id,
                                    is_request,
                                    option_value.u8,
                                    option_value.len));
  CU_ASSERT(oscore_ng_unsecure(&context_b,
                               COAP_MESSAGE_NON,
                               &empty_token,
                               &option_data,
                               request, sizeof(request),
                               is_request,
                               0) == OSCORE_NG_UNSECURE_RESULT_OK);

  /* Response #2 */
  is_request = false;
  CU_ASSERT(oscore_ng_secure(&context_b,
                             COAP_MESSAGE_NON,
                             &empty_token,
                             &option_data,
                             message_id,
                             request, sizeof(data),
                             is_request));
  oscore_ng_encode_option(&option_value, &option_data, is_request);
  CU_ASSERT(!option_data.kid_context.len);
  CU_ASSERT(oscore_ng_decode_option(&option_data,
                                    message_id,
                                    is_request,
                                    option_value.u8,
                                    option_value.len));
  CU_ASSERT(oscore_ng_unsecure(&context_a,
                               COAP_MESSAGE_NON,
                               &empty_token,
                               &option_data,
                               request, sizeof(request),
                               is_request,
                               0) == OSCORE_NG_UNSECURE_RESULT_OK);
  oscore_ng_clear_context(&context_a);
  CU_ASSERT(!list_head(context_a.anti_replay_list));
  oscore_ng_clear_context(&context_b);
  CU_ASSERT(!list_head(context_b.anti_replay_list));
}

static void
t_oscore_ng_deduplication(void) {
  oscore_ng_context_t context_a;
  oscore_ng_context_t context_b;
  uint8_t request[sizeof(data) + COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN];
  uint16_t message_id = 123;
  bool is_request = true;
  oscore_ng_option_data_t option_data;
  oscore_ng_option_value_t option_value;

  CU_ASSERT(oscore_ng_init_context(&context_a, &id_b, &id_a, &keying_material));
  CU_ASSERT(oscore_ng_init_context(&context_b, &id_a, &id_b, &keying_material));

  memcpy(request, data, sizeof(data));
  CU_ASSERT(oscore_ng_secure(&context_a,
                             COAP_MESSAGE_NON,
                             &token,
                             &option_data,
                             message_id,
                             request, sizeof(data),
                             is_request));
  CU_ASSERT(option_data.e2e_message_id == message_id);
  oscore_ng_encode_option(&option_value, &option_data, is_request);
  CU_ASSERT(oscore_ng_decode_option(&option_data,
                                    message_id,
                                    is_request,
                                    option_value.u8,
                                    option_value.len));
  CU_ASSERT(oscore_ng_unsecure(&context_b,
                               COAP_MESSAGE_NON,
                               &token,
                               &option_data,
                               request, sizeof(request),
                               is_request,
                               0) == OSCORE_NG_UNSECURE_RESULT_OK);
  CU_ASSERT(!memcmp(request, data, sizeof(data)));

  sleep(1);
  CU_ASSERT(oscore_ng_secure(&context_a,
                             COAP_MESSAGE_NON,
                             &token,
                             &option_data,
                             message_id,
                             request, sizeof(data),
                             is_request));
  oscore_ng_encode_option(&option_value, &option_data, is_request);
  CU_ASSERT(oscore_ng_decode_option(&option_data,
                                    message_id,
                                    is_request,
                                    option_value.u8,
                                    option_value.len));
  CU_ASSERT(oscore_ng_unsecure(&context_b,
                               COAP_MESSAGE_NON,
                               &token,
                               &option_data,
                               request,
                               sizeof(request),
                               is_request,
                               0) == OSCORE_NG_UNSECURE_RESULT_DUPLICATE);
  CU_ASSERT(!memcmp(request, data, sizeof(data)));
  oscore_ng_clear_context(&context_a);
  CU_ASSERT(!list_head(context_a.anti_replay_list));
  oscore_ng_clear_context(&context_b);
  CU_ASSERT(!list_head(context_b.anti_replay_list));
}

static void
t_oscore_ng_anti_replay(void) {
  oscore_ng_context_t context_a;
  oscore_ng_context_t context_b;
  uint8_t request[sizeof(data) + COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN];
  uint16_t message_id = 123;
  bool is_request = true;
  oscore_ng_option_data_t option_data;
  oscore_ng_option_value_t option_value;
  uint8_t request_copy[sizeof(data) + COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN];

  CU_ASSERT(oscore_ng_init_context(&context_a, &id_b, &id_a, &keying_material));
  CU_ASSERT(oscore_ng_init_context(&context_b, &id_a, &id_b, &keying_material));

  memcpy(request, data, sizeof(data));
  CU_ASSERT(oscore_ng_secure(&context_a,
                             COAP_MESSAGE_CON,
                             &token,
                             &option_data,
                             message_id,
                             request, sizeof(data),
                             is_request));
  memcpy(request_copy, request, sizeof(request_copy));
  oscore_ng_encode_option(&option_value, &option_data, is_request);
  CU_ASSERT(oscore_ng_decode_option(&option_data,
                                    message_id,
                                    is_request,
                                    option_value.u8,
                                    option_value.len));
  CU_ASSERT(oscore_ng_unsecure(&context_b,
                               COAP_MESSAGE_CON,
                               &token,
                               &option_data,
                               request, sizeof(request),
                               is_request,
                               0) == OSCORE_NG_UNSECURE_RESULT_OK);
  CU_ASSERT(!memcmp(request, data, sizeof(data)));

  /* send same request again */
  CU_ASSERT(oscore_ng_decode_option(&option_data,
                                    message_id,
                                    is_request,
                                    option_value.u8,
                                    option_value.len));
  CU_ASSERT(oscore_ng_unsecure(&context_b,
                               COAP_MESSAGE_CON,
                               &token,
                               &option_data,
                               request_copy, sizeof(request_copy),
                               is_request,
                               0) == OSCORE_NG_UNSECURE_RESULT_ERROR);
  oscore_ng_clear_context(&context_a);
  CU_ASSERT(!list_head(context_a.anti_replay_list));
  oscore_ng_clear_context(&context_b);
  CU_ASSERT(!list_head(context_b.anti_replay_list));
}

static void
t_oscore_ng_empty_option(void) {
  oscore_ng_option_data_t option_data;
  uint16_t message_id = 123;

  CU_ASSERT(oscore_ng_decode_option(&option_data, message_id, true, NULL, 0));
  CU_ASSERT(message_id == option_data.e2e_message_id);
}

/************************************************************************
 ** initialization
 ************************************************************************/

CU_pSuite
t_init_oscore_ng_tests(void) {
  CU_pSuite suite[5];

  suite[0] = CU_add_suite("OSCORE-NG", NULL, NULL);
  if (!suite[0]) {                        /* signal error */
    fprintf(stderr, "W: cannot add OSCORE-NG test suite (%s)\n",
            CU_get_error_msg());

    return NULL;
  }

#define OSCORE_NG_TEST(n)                                  \
  if (!CU_add_test(suite[0], #n, n)) {                     \
    fprintf(stderr, "W: cannot add OSCORE-NG test (%s)\n", \
            CU_get_error_msg());                           \
  }

  OSCORE_NG_TEST(t_oscore_ng_self);
  OSCORE_NG_TEST(t_oscore_ng_secure_unsecure);
  OSCORE_NG_TEST(t_oscore_ng_sps_sanity_check);
  OSCORE_NG_TEST(t_oscore_ng_strong_freshness);
  OSCORE_NG_TEST(t_oscore_ng_b2);
  OSCORE_NG_TEST(t_oscore_ng_deduplication);
  OSCORE_NG_TEST(t_oscore_ng_anti_replay);
  OSCORE_NG_TEST(t_oscore_ng_empty_option);

  return suite[0];
}

#else /* COAP_OSCORE_NG_SUPPORT */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void
dummy(void) {
}

#endif /* COAP_OSCORE_NG_SUPPORT */
