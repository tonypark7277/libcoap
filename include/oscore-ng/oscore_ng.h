/*
 * Copyright (c) 2022, Uppsala universitet.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/**
 * @file oscore_ng.h
 * @brief OSCORE-NG library
 */

#ifndef OSCORE_NG_H_
#define OSCORE_NG_H_

/**
 * @ingroup internal_api
 * @addtogroup oscore_ng_internal
 * @{
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define OSCORE_NG_MAX_TOKEN_LEN (12)
#define OSCORE_NG_E2E_MESSAGE_ID_LEN (2)
#define OSCORE_NG_MAX_TIMESTAMP_BYTES (5)
#define OSCORE_NG_MAX_ID_LEN (COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN \
                              - 1 /* Sender ID length */ \
                              - OSCORE_NG_E2E_MESSAGE_ID_LEN \
                              - OSCORE_NG_MAX_TIMESTAMP_BYTES)
#define OSCORE_NG_MAX_R1_LEN (8)
#define OSCORE_NG_MAX_R2_LEN (16)
#define OSCORE_NG_MAX_ID_CONTEXT_LEN (OSCORE_NG_MAX_R1_LEN \
                                      + OSCORE_NG_MAX_R2_LEN)
#define OSCORE_NG_OPTION_MAX_VALUE_LEN (1 /* flags || phase */ \
                                        + 1 /* timestamp-related header */ \
                                        + OSCORE_NG_MAX_TIMESTAMP_BYTES \
                                        + OSCORE_NG_MAX_TIMESTAMP_BYTES \
                                        + OSCORE_NG_MAX_TIMESTAMP_BYTES \
                                        + OSCORE_NG_E2E_MESSAGE_ID_LEN \
                                        + 1 /* s */ \
                                        + OSCORE_NG_MAX_ID_CONTEXT_LEN \
                                        + OSCORE_NG_MAX_ID_LEN)
#define OSCORE_NG_ACK_TIMEOUT (2 * 100) /* = 2 seconds */
#define OSCORE_NG_MAX_TRANSMIT_SPAN (45 * 100)
#define OSCORE_NG_FRESHNESS_THRESHOLD (785)
#define OSCORE_NG_PROCESSING_DELAY (200)

typedef coap_oscore_ng_keying_material_t oscore_ng_keying_material_t;

/**
 * Structure for holding an ID.
 */
typedef struct oscore_ng_id_t {
  uint8_t u8[OSCORE_NG_MAX_ID_LEN];
  uint8_t len;
} oscore_ng_id_t;

/**
 * Structure for holding an ID Context.
 */
typedef struct oscore_ng_id_context_t {
  uint8_t u8[OSCORE_NG_MAX_ID_CONTEXT_LEN];
  uint8_t len;
} oscore_ng_id_context_t;

/**
 * Structure for holding the data of an OSCORE-NG option.
 */
typedef struct oscore_ng_option_data_t {
  oscore_ng_id_t kid; /**< kid field */
  oscore_ng_id_context_t kid_context; /**< kid context field */
  uint64_t corresponding_tx_timestamp; /**< in centiseconds */
  uint64_t rx_timestamp; /**< in centiseconds */
  uint64_t tx_timestamp; /**< in centiseconds */
  uint16_t e2e_message_id; /**< end-to-end Message ID */
  uint_fast8_t phase; /**< @c PHASE_UNITs elapsed since the timeslot began */
  bool asking_for_resync; /**< r-flag */
  bool has_timestamps; /**< if any timestamps are present */
} oscore_ng_option_data_t;

/**
 * Structure for holding the wire format of an OSCORE-NG option.
 */
typedef struct oscore_ng_option_value_t {
  size_t len;
  uint8_t u8[OSCORE_NG_OPTION_MAX_VALUE_LEN];
} oscore_ng_option_value_t;

/**
 * Enumeration of the states of the B2 protocol.
 */
typedef enum oscore_ng_b2_stage_t {
  OSCORE_NG_B2_DISABLED = 0,/**< OSCORE_NG_B2_DISABLED */
  OSCORE_NG_B2_RUNNING,     /**< OSCORE_NG_B2_RUNNING */
  OSCORE_NG_B2_DONE,        /**< OSCORE_NG_B2_DONE */
} oscore_ng_b2_stage_t;

/**
 * Structure for holding data of an OSCORE-NG session.
 */
typedef struct oscore_ng_context_t {
  const oscore_ng_keying_material_t *keying_material;
  const oscore_ng_id_t *sender_id;
  oscore_ng_id_t recipient_id;
  oscore_ng_id_context_t id_context;
  uint64_t last_synchronization; /**< in centiseconds */
  int64_t delta; /**< clock difference in centiseconds */
  uint64_t pending_corresponding_tx_timestamp;  /**< in centiseconds */
  uint64_t pending_rx_timestamp; /**< in centiseconds */
  LIST_STRUCT(anti_replay_list);
  oscore_ng_b2_stage_t b2_stage;
  bool has_explicit_id_context;
} oscore_ng_context_t;

/**
 * Structure for holding anti-replay data.
 */
typedef struct oscore_ng_anti_replay_t {
  struct oscore_ng_anti_replay_t *next;
  uint32_t rx_timestamp;
  uint16_t e2e_message_id;
  union {
    uint16_t restored_tx_timestamp; /* for requests */
    uint8_t message_type; /* for responses */
  } u;
  bool was_request;
} oscore_ng_anti_replay_t;

/**
 * Enumeration of possible outcomes of @c oscore_ng_unsecure.
 */
typedef enum oscore_ng_unsecure_result_t {
  OSCORE_NG_UNSECURE_RESULT_ERROR,       /**< Inauthentic, old, or error */
  OSCORE_NG_UNSECURE_RESULT_OK,          /**< Authentic and fresh */
  OSCORE_NG_UNSECURE_RESULT_DUPLICATE,   /**< Received a duplicate */
  OSCORE_NG_UNSECURE_RESULT_B2_REQUEST_1,/**< OK and to be answered with RST */
} oscore_ng_unsecure_result_t;

/**
 * External function that provides non-contiguous timestamps.
 *
 * @return A timestamp in centiseconds or @c 0 on error.
 */
uint64_t oscore_ng_generate_timestamp(void);

/**
 * External function that provides cryptographic random numbers.
 *
 * @param dst     Destination where to put the cryptgraphic random numbers.
 * @param dst_len Size of @p dst in bytes.
 *
 * @return        0 on error and non-zero on success.
 */
int oscore_ng_csprng(void *dst, size_t dst_len);

/**
 * External function for allocating memory for anti-replay data.
 *
 * @return A pointer to the allocated memory or @c NULL on error.
 */
oscore_ng_anti_replay_t *oscore_ng_alloc_anti_replay(void);

/**
 * External function for freeing memory that was allocated to anti-replay data.
 *
 * @param anti_replay Pointer to the allocated memory.
 */
void oscore_ng_free_anti_replay(oscore_ng_anti_replay_t *anti_replay);

/**
 * Copies an ID.
 *
 * @param dst Buffer for storing the copy.
 * @param src Original ID.
 */
void oscore_ng_copy_id(
    oscore_ng_id_t *dst,
    const oscore_ng_id_t *src);

/**
 * Copies an ID Context.
 *
 * @param dst Buffer for storing the copy.
 * @param src Original ID context.
 */
void oscore_ng_copy_id_context(
    oscore_ng_id_context_t *dst,
    const oscore_ng_id_context_t *src);

/**
 * Compares two IDs.
 *
 * @param ida First ID.
 * @param idb Second ID.
 *
 * @return    True if both IDs are equal.
 */
bool oscore_ng_are_ids_equal(
    const oscore_ng_id_t *ida,
    const oscore_ng_id_t *idb);

/**
 * Compares two ID contexts.
 *
 * @param id_context_a First ID Context.
 * @param id_context_b Second ID Context.
 *
 * @return             True if both ID contexts are equal.
 */
bool oscore_ng_are_id_contexts_equal(
    const oscore_ng_id_context_t *id_context_a,
    const oscore_ng_id_context_t *id_context_b);

/**
 * Initializes OSCORE-NG keying material.
 *
 * @param keying_material   Buffer for storing the OSCORE-NG keying material.
 * @param master_secret     Session-scope pointer to the Master Secret.
 * @param master_secret_len Length of @p master_secret in bytes.
 * @param master_salt       Session-scope pointer to the Master Salt.
 * @param master_salt_len   Length of @p master_salt in bytes.
 */
void oscore_ng_init_keying_material(
    oscore_ng_keying_material_t *keying_material,
    const uint8_t *master_secret,
    size_t master_secret_len,
    const uint8_t *master_salt,
    size_t master_salt_len);

/**
 * Copies OSCORE-NG keying material.
 *
 * @param keying_material   Buffer for storing the OSCORE-NG keying material.
 * @param master_secret_dst Buffer for storing the Master Secret.
 * @param master_secret_src Pointer to the Master Secret.
 * @param master_secret_len Length of the Master Secret in bytes.
 * @param master_salt_dst   Buffer for storing the Master Salt.
 * @param master_salt_src   Pointer to the Master Salt.
 * @param master_salt_len   Length of the Master Salt in bytes.
 */
void oscore_ng_copy_keying_material(
    oscore_ng_keying_material_t *keying_material,
    uint8_t *master_secret_dst,
    const uint8_t *master_secret_src,
    size_t master_secret_len,
    uint8_t *master_salt_dst,
    const uint8_t *master_salt_src,
    size_t master_salt_len);

/**
 * Spawns an OSCORE-NG session.
 *
 * @param context         An uninitialized OSCORE-NG context.
 * @param recipient_id    The Recipient ID.
 * @param sender_id       The Sender ID.
 * @param keying_material The Master Secret and Master Salt.
 *
 * @return                0 on error and non-zero on success.
 */
int oscore_ng_init_context(
    oscore_ng_context_t *context,
    const oscore_ng_id_t *recipient_id,
    const oscore_ng_id_t *sender_id,
    const oscore_ng_keying_material_t *keying_material);

/**
 * Erases all session-specfic information.
 *
 * @param context The OSCORE-NG context.
 */
void oscore_ng_clear_context(
    oscore_ng_context_t *context);

/**
 * Encodes the OSCORE-NG option for a CoAP message.
 *
 * @param option_value Buffer for storing the encoded OSCORE-NG option.
 * @param option_data  Contents of the OSCORE-NG option.
 * @param is_request   If true, the CoAP message is a request.
 */
void oscore_ng_encode_option(
    oscore_ng_option_value_t *option_value,
    const oscore_ng_option_data_t *option_data,
    bool is_request);

/**
 * Decodes the OSCORE-NG option of an OSCORE-NG message.
 *
 * @param option_data  Buffer for storing contents of the OSCORE-NG option.
 * @param message_id   The Message ID of the OSCORE-NG message.
 * @param is_request   If true, the OSCORE-NG message is a request.
 * @param option_value The OSCORE-NG option value.
 * @param option_len   Length of @p option_value in bytes.
 *
 * @return             0 on error and non-zero on success.
 */
int oscore_ng_decode_option(
    oscore_ng_option_data_t *option_data,
    uint16_t message_id,
    bool is_request,
    const uint8_t *option_value,
    size_t option_len);

/**
 * Encrypts and authenticates a CoAP message.
 *
 * @param context        The OSCORE-NG context.
 * @param message_type   The CoAP message type.
 * @param original_token The original Token.
 * @param option_data    Contents for the OSCORE-NG option.
 * @param e2e_message_id The end-to-end Message ID.
 * @param plaintext      The CoAP payload of the CoAP message.
 * @param plaintext_len  Length of the CoAP payload in bytes.
 * @param is_request     If true, the CoAP message is a request.
 *
 * @return              0 on error and non-zero on success.
 */
int oscore_ng_secure(
    oscore_ng_context_t *context,
    uint_fast8_t message_type,
    const coap_bin_const_t *original_token,
    oscore_ng_option_data_t *option_data,
    uint16_t e2e_message_id,
    uint8_t *plaintext, size_t plaintext_len,
    bool is_request);

/**
 * Decrypts and checks an OSCORE-NG message for authenticity and freshness.
 *
 * @param context        The OSCORE-NG context.
 * @param message_type   The CoAP message type of the OSCORE-NG message.
 * @param original_token The original Token.
 * @param option_data    Contents of the OSCORE-NG option.
 * @param ciphertext     The CoAP payload of the OSCORE-NG message.
 * @param ciphertext_len Length of @p ciphertext in bytes.
 * @param is_request     If true, the OSCORE-NG message is a request.
 * @param rx_timestamp   The RX timestamp or 0 if unavailable.
 *
 * @return               A specific result code.
 */
enum oscore_ng_unsecure_result_t oscore_ng_unsecure(
    oscore_ng_context_t *context,
    uint_fast8_t message_type,
    const coap_bin_const_t *original_token,
    oscore_ng_option_data_t *option_data,
    uint8_t *ciphertext, size_t ciphertext_len,
    bool is_request,
    uint64_t rx_timestamp);

/**
 * Enables the B2 protocol for session key establishment.
 *
 * @param context The OSCORE-NG context.
 */
void oscore_ng_start_b2(
    oscore_ng_context_t *context);

/**
 * Sets a new ID Context.
 *
 * @param context                The OSCORE-NG context.
 * @param id_context             The new ID Context.
 * @param is_explicit_id_context If true, @p id_context will be in-lined.
 */
void oscore_ng_set_id_context(
    oscore_ng_context_t *context,
    const oscore_ng_id_context_t *id_context,
    bool is_explicit_id_context);

/**
 * Performs a self-test.
 *
 * @return 0 on error and non-zero on success.
 */
int oscore_ng_self_test(void);

/** @} */

#endif /* OSCORE_NG_H_ */
