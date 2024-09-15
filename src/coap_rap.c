/*
 * coap_rap.c -- remote attestation and key exchange
 *
 * Copyright (C) 2021-2023 Uppsala universitet
 * Copyright (C) 2025 Siemens AG
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_rap.c
 * @brief remote attestation and key exchange
 */

#include "coap3/coap_internal.h"

#if COAP_RAP_SUPPORT && COAP_CLIENT_SUPPORT
#define PADDING_SIZE (COAP_RAP_MAX_COOKIE_SIZE)
#define PAYLOAD_MARKER_SIZE (1)
#define ID_CONTEXT_SIZE (8)

#if WITH_CONTIKI
#define HASH_CTX
#define HASH_CTX_COMMA
#else /* ! WITH_CONTIKI */
#define HASH_CTX &ctx
#define HASH_CTX_COMMA &ctx,
#endif /* ! WITH_CONTIKI */

static void clean_up(coap_session_t *session);
static PT_THREAD(generate_ephemeral_key_pair(coap_rap_context_t *rap_context));
static int knock(coap_session_t *session);
static coap_response_t on_cookie(coap_session_t *session,
                                 const coap_pdu_t *sent,
                                 const coap_pdu_t *received,
                                 const coap_mid_t mid);
static PT_THREAD(initiate_registration(coap_session_t *session));
static coap_response_t on_report(coap_session_t *session,
                                 const coap_pdu_t *sent,
                                 const coap_pdu_t *received,
                                 const coap_mid_t mid);
#if WITH_IRAP
static PT_THREAD(reconstruct_sms_public_key(coap_rap_context_t *rap_context));
#else /* ! WITH_IRAP */
static PT_THREAD(verify_sm_report(coap_rap_context_t *rap_context));
#endif /* ! WITH_IRAP */
#if WITH_TRAP && ! WITH_IRAP
static PT_THREAD(verify_tee_report(
                     uint8_t clients_fhmqv_mic[COAP_RAP_FHMQV_MIC_SIZE],
                     coap_rap_context_t *rap_context,
                     uint8_t secret[ECC_CURVE_P_256_SIZE]));
#else /* ! WITH_TRAP || WITH_IRAP */
static PT_THREAD(verify_tee_report(
                     coap_rap_context_t *rap_context,
                     uint8_t secret[ECC_CURVE_P_256_SIZE]));
#endif /* ! WITH_TRAP || WITH_IRAP */
static void on_timeout(coap_session_t *session,
                       const coap_pdu_t *sent,
                       const coap_nack_reason_t reason,
                       const coap_mid_t mid);
static int init_oscore_ng_session(coap_session_t *session,
                                  const coap_bin_const_t *recipient_id);

const char knock_path[] = "kno";
const size_t knock_path_length = sizeof(knock_path) - 1;
const char register_path[] = "reg";
const size_t register_path_length = sizeof(register_path) - 1;

coap_rap_result_t
coap_rap_initiate(coap_session_t *session,
                  const coap_rap_config_t *config
#if WITH_TRAP && ! WITH_IRAP
                  , uint8_t clients_fhmqv_mic[COAP_RAP_FHMQV_MIC_SIZE]
#endif /* WITH_TRAP && ! WITH_IRAP */
                 ) {
  PT_BEGIN(&session->rap_pt);

  assert(!session->rap_context);
  assert(!session->oscore_ng_context);
  if (!session->context->oscore_ng) {
    coap_log_err("coap_rap_initiate: call coap_oscore_ng_init first\n");
    return COAP_RAP_RESULT_EXITED;
  }

  /* allocate context */
  session->rap_context = coap_malloc_type(
                             COAP_RAP_CLIENT_CONTEXT,
                             sizeof(coap_rap_context_t));
  if (!session->rap_context) {
    coap_log_err("coap_rap_initiate: coap_malloc_type failed\n");
    PT_EXIT(&session->rap_pt);
  }
  coap_session_reference(session);
  session->rap_context->config = config;
  session->rap_context->result = 0;

  /* generate ephemeral key pair */
#if WITH_CONTIKI
  PT_WAIT_UNTIL(&session->rap_pt, process_mutex_try_lock(ecc_get_mutex()));
#endif /* WITH_CONTIKI */
  if (ecc_enable(&ecc_curve_p_256)) {
    goto error_1;
  }
  PT_SPAWN(&session->rap_pt,
           &session->rap_context->sub_pt,
           generate_ephemeral_key_pair(session->rap_context));
  ecc_disable();
  if (session->rap_context->result) {
    coap_log_err("coap_rap_initiate: generate_ephemeral_key_pair failed\n");
    goto error_1;
  }

  /* send /kno request */
  if (!knock(session)) {
    goto error_1;
  }

  /* wait for /kno response */
  coap_register_response_handler(session->context, on_cookie);
  coap_register_nack_handler(session->context, on_timeout);
  session->rap_context->msg.kno.cookie_size = 0;
  PT_YIELD_UNTIL(&session->rap_pt, session->rap_context->result);
  if (session->rap_context->result < 0) {
    goto error_1;
  }
  session->rap_context->result = 0;
  assert(session->rap_context->msg.kno.cookie_size);
  assert(session->rap_context->msg.kno.cookie_size
         <= COAP_RAP_MAX_COOKIE_SIZE);

  /* send /reg request */
#if WITH_CONTIKI
  PT_WAIT_UNTIL(&session->rap_pt, process_mutex_try_lock(ecc_get_mutex()));
#endif /* WITH_CONTIKI */
  if (ecc_enable(&ecc_curve_p_256)) {
    goto error_1;
  }
  PT_SPAWN(&session->rap_pt,
           &session->rap_context->sub_pt,
           initiate_registration(session));
  ecc_disable();
  if (session->rap_context->result) {
    coap_log_err("coap_rap_initiate: initiate_registration failed\n");
    goto error_1;
  }

  /* wait for /reg response */
  coap_register_response_handler(session->context, on_report);
  PT_YIELD_UNTIL(&session->rap_pt, session->rap_context->result);
  if (session->rap_context->result < 0) {
    goto error_1;
  }
  session->rap_context->result = 0;

#if WITH_CONTIKI
  PT_WAIT_UNTIL(&session->rap_pt, process_mutex_try_lock(ecc_get_mutex()));
#endif /* WITH_CONTIKI */
  if (ecc_enable(&ecc_curve_p_256)) {
    goto error_1;
  }

#if WITH_IRAP
  PT_SPAWN(&session->rap_pt,
           &session->rap_context->sub_pt,
           reconstruct_sms_public_key(session->rap_context));
  if (session->rap_context->result) {
    coap_log_err("coap_rap_initiate: reconstruct_sms_public_key failed\n");
    goto error_2;
  }
#else /* ! WITH_IRAP */
  PT_SPAWN(&session->rap_pt,
           &session->rap_context->sub_pt,
           verify_sm_report(session->rap_context));
  if (session->rap_context->result) {
    coap_log_err("coap_rap_initiate: received invalid SM report\n");
    goto error_2;
  }
#endif /* ! WITH_IRAP */

  /* verify TEE report */
  {
    uint8_t secret[ECC_CURVE_P_256_SIZE];
#if WITH_TRAP && ! WITH_IRAP
    PT_SPAWN(&session->rap_pt,
             &session->rap_context->sub_pt,
             verify_tee_report(clients_fhmqv_mic,
                               session->rap_context,
                               secret));
#else /* ! WITH_TRAP || WITH_IRAP */
    PT_SPAWN(&session->rap_pt,
             &session->rap_context->sub_pt,
             verify_tee_report(session->rap_context, secret));
#endif /* ! WITH_TRAP || WITH_IRAP */
    if (session->rap_context->result) {
      coap_log_err("coap_rap_initiate: received invalid TEE report\n");
      goto error_2;
    }
    if (!config->keying_material_setter(config->recipient_id,
                                        secret,
                                        sizeof(secret))) {
      coap_log_err("coap_rap_initiate: keying_material_setter failed\n");
      goto error_2;
    }
  }

  ecc_disable();

  /* init OSCORE-NG session */
  if (!init_oscore_ng_session(session, config->recipient_id)) {
    goto error_1;
  }

  clean_up(session);
  PT_END(&session->rap_pt);
error_2:
  ecc_disable();
error_1:
  clean_up(session);
  PT_EXIT(&session->rap_pt);
}

static void
clean_up(coap_session_t *session) {
  coap_free_type(COAP_RAP_CLIENT_CONTEXT, session->rap_context);
  session->rap_context = NULL;
  coap_register_response_handler(session->context, NULL);
  coap_register_nack_handler(session->context, NULL);
  coap_session_release(session);
}

static
PT_THREAD(generate_ephemeral_key_pair(coap_rap_context_t *rap_context)) {
#if ! WITH_TRAP
  uint8_t ephemeral_public_key[ECC_CURVE_P_256_SIZE * 2];
#endif /* ! WITH_TRAP */

  PT_BEGIN(&rap_context->sub_pt);

#if WITH_TRAP
  PT_SPAWN(&rap_context->sub_pt,
           ecc_get_protothread(),
           ecc_generate_key_pair(rap_context->my.ephemeral_public_key,
                                 rap_context->my.ephemeral_private_key,
                                 &rap_context->result));
#else /* ! WITH_TRAP */
  PT_SPAWN(&rap_context->sub_pt,
           ecc_get_protothread(),
           ecc_generate_key_pair(ephemeral_public_key,
                                 rap_context->my.ephemeral_private_key,
                                 &rap_context->result));
#endif /* ! WITH_TRAP */

#if ! WITH_TRAP
  if (rap_context->result) {
    coap_log_err("generate_ephemeral_key_pair: "
                 "ecc_generate_key_pair failed\n");
    PT_EXIT(&rap_context->sub_pt);
  }
  ecc_compress_public_key(ephemeral_public_key,
                          rap_context->my.ephemeral_public_key_compressed);
#endif /* ! WITH_TRAP */

  PT_END(&rap_context->sub_pt);
}

static int
knock(coap_session_t *session) {
  coap_pdu_t *pdu = coap_pdu_init(COAP_MESSAGE_CON,
                                  COAP_REQUEST_CODE_GET,
                                  coap_new_message_id(session),
                                  coap_opt_encode_size(COAP_OPTION_URI_PATH,
                                                       knock_path_length)
                                  + PAYLOAD_MARKER_SIZE
                                  + PADDING_SIZE);
  if (!pdu) {
    coap_log_err("knock: coap_pdu_init failed\n");
    return 0;
  }
  if (!coap_add_option(pdu,
                       COAP_OPTION_URI_PATH,
                       knock_path_length,
                       (const uint8_t *)knock_path)) {
    coap_log_err("knock: coap_add_option failed\n");
    coap_delete_pdu(pdu);
    return 0;
  }
  uint8_t *payload = coap_add_data_after(pdu, PADDING_SIZE);
  if (!payload) {
    coap_log_err("knock: coap_add_data_after failed\n");
    coap_delete_pdu(pdu);
    return 0;
  }
  memset(payload, 0, PADDING_SIZE);
  return coap_send(session, pdu) != COAP_INVALID_MID;
}

static coap_response_t
on_cookie(coap_session_t *session,
          const coap_pdu_t *sent,
          const coap_pdu_t *received,
          const coap_mid_t mid) {
  (void)sent;
  (void)mid;
  coap_rap_context_t *rap_context = session->rap_context;
  const uint8_t *cookie;

  assert(rap_context);
  if (!coap_get_data(received, &rap_context->msg.kno.cookie_size, &cookie)
      || !rap_context->msg.kno.cookie_size
      || (rap_context->msg.kno.cookie_size > COAP_RAP_MAX_COOKIE_SIZE)) {
    /* TODO adapt libcoap to continue retransmitting */
    rap_context->result = -1;
    rap_context->config->resume();
    return COAP_RESPONSE_FAIL;
  }
  memcpy(rap_context->msg.kno.cookie,
         cookie,
         rap_context->msg.kno.cookie_size);
  rap_context->result = 1;
  rap_context->config->resume();
  return COAP_RESPONSE_OK;
}

static
PT_THREAD(initiate_registration(coap_session_t *session)) {
  coap_rap_context_t *rap_context = session->rap_context;
#if ! WITH_TRAP
  uint8_t signature[COAP_RAP_SIGNATURE_SIZE];
#endif /* ! WITH_TRAP */

  PT_BEGIN(&rap_context->sub_pt);

#if ! WITH_TRAP
  /* sign our compressed ephemeral public key */
  {
#if ! WITH_CONTIKI
    sha_256_context_t ctx;
#endif /* ! WITH_CONTIKI */
    uint8_t hash[SHA_256_DIGEST_LENGTH];

    /*
     * Following the basic SIGMA protocol, we sign our ephemeral public key
     * and a nonce from the peer. However, to save bandwidth, we use the cookie
     * as nonce, which is not completely fresh. This enables impersonation
     * attacks if our ephemeral private key leaks while the cookie is still
     * valid. Yet, even when using a fresh nonce, the basic SIGMA protocol is
     * vulnerable to impersonation attacks if our ephemeral private key leaks
     * during the course of the basic SIGMA protocol.
     */
    SHA_256.init(HASH_CTX);
    SHA_256.update(HASH_CTX_COMMA
                   rap_context->my.ephemeral_public_key_compressed,
                   sizeof(rap_context->my.ephemeral_public_key_compressed));
    SHA_256.update(HASH_CTX_COMMA
                   rap_context->msg.kno.cookie,
                   rap_context->msg.kno.cookie_size);
    SHA_256.finalize(HASH_CTX_COMMA
                     hash);
    PT_SPAWN(&rap_context->sub_pt,
             ecc_get_protothread(),
             ecc_sign(hash,
                      rap_context->config->my_private_key,
                      signature,
                      &rap_context->result));
  }
  if (rap_context->result) {
    coap_log_err("initiate_registration: ecc_sign failed\n");
    PT_EXIT(&rap_context->sub_pt);
  }
#endif /* ! WITH_TRAP */

  {
    size_t payload_size;
#if WITH_IRAP
    rap_reg_request_t reg_request;
    reg_request.cookie = rap_context->msg.kno.cookie;
    reg_request.cookie_size = rap_context->msg.kno.cookie_size;
    ecc_compress_public_key(rap_context->my.ephemeral_public_key,
                            reg_request.ephemeral_public_key_compressed);
    if (rap_context->config->cert_chain) {
      reg_request.out_cert_chain = *rap_context->config->cert_chain;
    } else {
      reg_request.out_cert_chain.length = 0;
      reg_request.out_cert_chain.s = NULL;
    }
    reg_request.tee_tci_version = 0;
    payload_size = rap_get_reg_requests_payload_size(&reg_request);
#else /* ! WITH_IRAP */
    payload_size = (1 + ECC_CURVE_P_256_SIZE)
#if ! WITH_TRAP
                   + COAP_RAP_SIGNATURE_SIZE
#endif /* ! WITH_TRAP */
                   + rap_context->msg.kno.cookie_size;
#endif /* ! WITH_IRAP */

    coap_pdu_t *pdu = coap_pdu_init(
                          COAP_MESSAGE_CON,
                          COAP_REQUEST_CODE_GET,
                          coap_new_message_id(session),
                          coap_opt_encode_size(COAP_OPTION_URI_PATH,
                                               register_path_length)
#if WITH_IRAP
                          + coap_opt_encode_size(
                              COAP_OPTION_OSCORE,
                              1 + session->context->oscore_ng->sender_id.len)
#endif /* WITH_IRAP */
                          + PAYLOAD_MARKER_SIZE
                          + payload_size);
    if (!pdu) {
      coap_log_err("initiate_registration: coap_pdu_init failed\n");
      goto error;
    }
#if WITH_IRAP
    {
      uint8_t oscore_ng_option_value[1 + OSCORE_NG_MAX_ID_LEN];
      oscore_ng_option_value[0] = 0;
      memcpy(oscore_ng_option_value + 1,
             session->context->oscore_ng->sender_id.u8,
             session->context->oscore_ng->sender_id.len);
      if (!coap_add_option(pdu,
                           COAP_OPTION_OSCORE,
                           1 + session->context->oscore_ng->sender_id.len,
                           oscore_ng_option_value)) {
        coap_log_err("initiate_registration: coap_add_option failed\n");
        coap_delete_pdu(pdu);
        goto error;
      }
    }
#endif /* WITH_IRAP */
    if (!coap_add_option(pdu,
                         COAP_OPTION_URI_PATH,
                         register_path_length,
                         (const uint8_t *)register_path)) {
      coap_log_err("initiate_registration: coap_add_option failed\n");
      coap_delete_pdu(pdu);
      goto error;
    }
    {
      uint8_t *pdu_data = coap_add_data_after(pdu, payload_size);
      if (!pdu_data) {
        coap_log_err("initiate_registration: coap_add_data_after failed\n");
        coap_delete_pdu(pdu);
        goto error;
      }
#if WITH_IRAP
      if (!rap_write_reg_request(&reg_request, pdu_data, payload_size)) {
        coap_log_err("initiate_registration: rap_write_reg_request failed\n");
        coap_delete_pdu(pdu);
        goto error;
      }
#else /* ! WITH_IRAP */
#if WITH_TRAP
      ecc_compress_public_key(rap_context->my.ephemeral_public_key, pdu_data);
      pdu_data += 1 + ECC_CURVE_P_256_SIZE;
#else /* ! WITH_TRAP */
      memcpy(pdu_data,
             rap_context->my.ephemeral_public_key_compressed,
             sizeof(rap_context->my.ephemeral_public_key_compressed));
      pdu_data += sizeof(rap_context->my.ephemeral_public_key_compressed);
      memcpy(pdu_data, signature, sizeof(signature));
      pdu_data += sizeof(signature);
#endif /* ! WITH_TRAP */
      memcpy(pdu_data,
             rap_context->msg.kno.cookie,
             rap_context->msg.kno.cookie_size);
#endif /* ! WITH_IRAP */
    }
    rap_context->result = coap_send(session, pdu) == COAP_INVALID_MID;
  }
  PT_END(&rap_context->sub_pt);
error:
  rap_context->result = -1;
  PT_EXIT(&rap_context->sub_pt);
}

static coap_response_t
on_report(coap_session_t *session,
          const coap_pdu_t *sent,
          const coap_pdu_t *received,
          const coap_mid_t mid) {
  (void)sent;
  (void)mid;
  coap_rap_context_t *rap_context = session->rap_context;
  size_t payload_size;
  const uint8_t *payload;

  assert(rap_context);
  if (!coap_get_data(received, &payload_size, &payload)) {
    coap_log_err("on_report: coap_get_data failed\n");
    goto error;
  }
#if WITH_IRAP
  rap_context->msg.reg.rx_timestamp = oscore_ng_generate_timestamp();
  if (!rap_context->msg.reg.rx_timestamp) {
    coap_log_err("on_report: oscore_ng_generate_timestamp failed\n");
    goto error;
  }
  if (!rap_parse_reg_response(payload,
                              payload_size,
                              &rap_context->msg.reg.payload)) {
    coap_log_err("on_report: rap_parse_reg_response failed\n");
    goto error;
  }
  {
    const tiny_dice_tci_mapping_t l1_tci_mapping = {
      rap_context->config->expected_sm_hash, rap_context->config->sm_version
    };
    tiny_dice_decompress_cert_chain(rap_context->config->recipient_id->s,
                                    NULL,
                                    rap_context->config->recipient_id->length,
                                    &l1_tci_mapping,
                                    &rap_context->msg.reg.payload.cert_chain);
    if (!rap_context->msg.reg.payload.cert_chain.length
        || (rap_context->msg.reg.payload.cert_chain.length > 1)
        || !rap_context->msg.reg.payload.cert_chain.certs[0].tci_digest
        || (rap_context->msg.reg.payload.cert_chain.certs[0].tci_digest
            != rap_context->config->expected_sm_hash)) {
      coap_log_err("on_report: unacceptable certificate chain\n");
      goto error;
    }
  }
  rap_context->tee.ephemeral_public_key_compressed =
      rap_context->msg.reg.payload.ephemeral_public_key_compressed;
  if (rap_context->msg.reg.payload.tee_tci_version
      != rap_context->config->tee_version) {
    coap_log_err("on_report: untrusted TEE version\n");
    goto error;
  }
  if (!coap_oscore_ng_parse_option(&rap_context->msg.reg.option_data,
                                   received,
                                   0)) {
    coap_log_err("on_report: coap_oscore_ng_parse_option failed\n");
    goto error;
  }
#else /* ! WITH_IRAP */
  /* validate length */
  if (payload_size != COAP_RAP_MAX_REPORT_SIZE) {
    coap_log_err("on_report: "
                 "The attestation report has an invalid length %zu != %u\n",
                 payload_size,
                 COAP_RAP_MAX_REPORT_SIZE);
    goto error;
  }

  /* parse */
  rap_context->sm.public_key_compressed[0] =
      2 | (*payload & 1);
  rap_context->tee.ephemeral_public_key_compressed[0] =
      2 | ((*payload & 2) >> 1);
  payload++;
  memcpy(rap_context->sm.public_key_compressed + 1,
         payload,
         ECC_CURVE_P_256_SIZE);
  payload += ECC_CURVE_P_256_SIZE;
  memcpy(rap_context->msg.reg.bootloaders_signature,
         payload,
         sizeof(rap_context->msg.reg.bootloaders_signature));
  payload += sizeof(rap_context->msg.reg.bootloaders_signature);
  memcpy(rap_context->tee.ephemeral_public_key_compressed + 1,
         payload,
         ECC_CURVE_P_256_SIZE);
  payload += ECC_CURVE_P_256_SIZE;
#if WITH_TRAP
  memcpy(rap_context->msg.reg.tees_fhmqv_mic,
         payload,
         sizeof(rap_context->msg.reg.tees_fhmqv_mic));
#else /* ! WITH_TRAP */
  memcpy(rap_context->msg.reg.sms_signature,
         payload,
         sizeof(rap_context->msg.reg.sms_signature));
#endif /* ! WITH_TRAP */
#endif /* ! WITH_IRAP */

  rap_context->result = 1;
  rap_context->config->resume();
  return COAP_RESPONSE_OK;
error:
  /* TODO adapt libcoap to continue retransmitting */
  rap_context->result = -1;
  rap_context->config->resume();
  return COAP_RESPONSE_FAIL;
}

#if WITH_IRAP
static
PT_THREAD(reconstruct_sms_public_key(coap_rap_context_t *rap_context)) {
  PT_BEGIN(&rap_context->sub_pt);

  memcpy(rap_context->sm.public_key,
         rap_context->config->root_of_trusts_public_key,
         sizeof(rap_context->sm.public_key));
  if (!rap_context->msg.reg.payload.cert_chain.length) {
    rap_context->result = 0;
    PT_EXIT(&rap_context->sub_pt);
  }

  if (rap_context->msg.reg.payload.cert_chain.length > 2) {
    coap_log_err("reconstruct_sms_public_key: overlong certificate chain\n");
    rap_context->result = 1;
    PT_EXIT(&rap_context->sub_pt);
  }

  if (rap_context->msg.reg.payload.cert_chain.certs[0].curve
      != TINY_DICE_CURVE_SECP256R1) {
    coap_log_err("reconstruct_sms_public_key: unsupported curve\n");
    rap_context->result = 1;
    PT_EXIT(&rap_context->sub_pt);
  }

  for (rap_context->reconstruct.i = 0;
       rap_context->reconstruct.i < rap_context->msg.reg.payload.cert_chain.length;
       rap_context->reconstruct.i++) {
    tiny_dice_cert_t *current_cert =
        rap_context->msg.reg.payload.cert_chain.certs + rap_context->reconstruct.i;

    /* compute digest */
    {
      uint8_t cert[TINY_DICE_MAX_CERT_SIZE];
      cbor_writer_state_t state;
      size_t cert_size;

      cbor_init_writer(&state, cert, sizeof(cert));
      if (rap_context->reconstruct.i) {
        current_cert->issuer_id = rap_context->reconstruct.cert_hash;
      } else {
        current_cert->issuer_id = NULL;
        current_cert->issuer_hash = TINY_DICE_HASH_SHA256;
      }
      tiny_dice_write_cert(&state, current_cert);
      cert_size = cbor_end_writer(&state);
      if (!cert_size) {
        rap_context->result = 1;
        coap_log_err("reconstruct_sms_public_key: "
                     "tiny_dice_prepend_cert failed\n");
        PT_EXIT(&rap_context->sub_pt);
      }
      SHA_256.hash(cert, cert_size, rap_context->reconstruct.cert_hash);
    }

    {
      uint8_t current_ca_public_key[ECC_CURVE_P_256_SIZE * 2];

      memcpy(current_ca_public_key,
             rap_context->sm.public_key,
             sizeof(current_ca_public_key));

      /* decompress reconstruction data */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
      PT_SPAWN(&rap_context->sub_pt,
               ecc_get_protothread(),
               ecc_decompress_public_key(current_cert->reconstruction_data,
                                         rap_context->sm.public_key,
                                         &rap_context->result));
#pragma GCC diagnostic pop
      if (rap_context->result) {
        coap_log_err("reconstruct_sms_public_key: decompress_public_key failed\n");
        PT_EXIT(&rap_context->sub_pt);
      }

      /* validate reconstruction data */
      PT_SPAWN(&rap_context->sub_pt,
               ecc_get_protothread(),
               ecc_validate_public_key(rap_context->sm.public_key,
                                       &rap_context->result));
      if (rap_context->result) {
        coap_log_err("reconstruct_sms_public_key: validate_public_key failed\n");
        PT_EXIT(&rap_context->sub_pt);
      }

      /* restore public key in place */
      PT_SPAWN(&rap_context->sub_pt,
               ecc_get_protothread(),
               ecc_reconstruct_ecqv_public_key(rap_context->reconstruct.cert_hash,
                                               rap_context->sm.public_key,
                                               current_ca_public_key,
                                               rap_context->sm.public_key,
                                               &rap_context->result));
      if (rap_context->result) {
        coap_log_err("reconstruct_sms_public_key: "
                     "reconstruct_ecqv_public_key failed\n");
        PT_EXIT(&rap_context->sub_pt);
      }
    }
  }

  PT_END(&rap_context->sub_pt);
}
#else /* ! WITH_IRAP */
static
PT_THREAD(verify_sm_report(coap_rap_context_t *rap_context)) {
  uint8_t sm_report_hash[SHA_256_DIGEST_LENGTH];
#if ! WITH_CONTIKI
  sha_256_context_t ctx;
#endif /* ! WITH_CONTIKI */

  PT_BEGIN(&rap_context->sub_pt);

  SHA_256.init(HASH_CTX);
  SHA_256.update(HASH_CTX_COMMA
                 rap_context->config->expected_sm_hash,
                 SHA_256_DIGEST_LENGTH);
  SHA_256.update(HASH_CTX_COMMA
                 rap_context->sm.public_key_compressed,
                 sizeof(rap_context->sm.public_key_compressed));
  SHA_256.finalize(HASH_CTX_COMMA
                   sm_report_hash);
  PT_SPAWN(&rap_context->sub_pt,
           ecc_get_protothread(),
           ecc_verify(rap_context->msg.reg.bootloaders_signature,
                      sm_report_hash,
                      rap_context->config->root_of_trusts_public_key,
                      &rap_context->result));

  PT_END(&rap_context->sub_pt);
}
#endif /* ! WITH_IRAP */

#if WITH_TRAP && ! WITH_IRAP
static
PT_THREAD(verify_tee_report(
              uint8_t clients_fhmqv_mic[COAP_RAP_FHMQV_MIC_SIZE],
              coap_rap_context_t *rap_context,
              uint8_t secret[ECC_CURVE_P_256_SIZE])) {
#else /* ! WITH_TRAP || WITH_IRAP */
static
PT_THREAD(verify_tee_report(
              coap_rap_context_t *rap_context,
              uint8_t secret[ECC_CURVE_P_256_SIZE])) {
#endif /* ! WITH_TRAP || WITH_IRAP */
#if ! WITH_TRAP
  uint8_t sms_public_key[ECC_CURVE_P_256_SIZE * 2];
#endif /* ! WITH_TRAP */

  PT_BEGIN(&rap_context->sub_pt);

#if WITH_TRAP
  /* decompress TEE's ephemeral public key */
  PT_SPAWN(&rap_context->sub_pt,
           ecc_get_protothread(),
           ecc_decompress_public_key(
               rap_context->tee.ephemeral_public_key_compressed,
               rap_context->tee.ephemeral_public_key,
               &rap_context->result));
  if (rap_context->result) {
    coap_log_err("verify_tee_report: "
                 "decompression of TEE's ephemeral public key failed\n");
    PT_EXIT(&rap_context->sub_pt);
  }
  PT_SPAWN(&rap_context->sub_pt,
           ecc_get_protothread(),
           ecc_validate_public_key(rap_context->tee.ephemeral_public_key,
                                   &rap_context->result));
  if (rap_context->result) {
    coap_log_err("verify_tee_report: "
                 "validation of TEE's ephemeral public key failed\n");
    PT_EXIT(&rap_context->sub_pt);
  }
#endif /* WITH_TRAP */

#if ! WITH_IRAP
  /* decompress SM's public key */
#if WITH_TRAP
  PT_SPAWN(&rap_context->sub_pt,
           ecc_get_protothread(),
           ecc_decompress_public_key(rap_context->sm.public_key_compressed,
                                     rap_context->sm.public_key,
                                     &rap_context->result));
#else /* ! WITH_TRAP */
  PT_SPAWN(&rap_context->sub_pt,
           ecc_get_protothread(),
           ecc_decompress_public_key(rap_context->sm.public_key_compressed,
                                     sms_public_key,
                                     &rap_context->result));
#endif /* ! WITH_TRAP */
  if (rap_context->result) {
    coap_log_err("verify_tee_report: "
                 "decompression of SM's public key failed\n");
    PT_EXIT(&rap_context->sub_pt);
  }
#endif /* ! WITH_IRAP */

#if WITH_TRAP
  union {
    struct {
      uint8_t de[SHA_256_DIGEST_LENGTH];
    } s1;
    struct {
      uint8_t sigma[ECC_CURVE_P_256_SIZE];
      uint8_t ikm[ECC_CURVE_P_256_SIZE * 8];
    } s2;
    struct {
      uint8_t okm[ECC_CURVE_P_256_SIZE * 2];
#if ! WITH_IRAP
      uint8_t fhmqv_mic[SHA_256_DIGEST_LENGTH];
#endif /* ! WITH_IRAP */
    } s3;
  } stack;

  {
#if ! WITH_CONTIKI
    sha_256_context_t ctx;
#endif /* ! WITH_CONTIKI */

    SHA_256.init(HASH_CTX);
    SHA_256.update(HASH_CTX_COMMA
                   rap_context->my.ephemeral_public_key,
                   sizeof(rap_context->my.ephemeral_public_key));
    SHA_256.update(HASH_CTX_COMMA
                   rap_context->tee.ephemeral_public_key,
                   sizeof(rap_context->tee.ephemeral_public_key));
    SHA_256.update(HASH_CTX_COMMA
                   rap_context->config->my_public_key,
                   2 * ECC_CURVE_P_256_SIZE);
    SHA_256.update(HASH_CTX_COMMA
                   rap_context->sm.public_key,
                   sizeof(rap_context->sm.public_key));
    SHA_256.finalize(HASH_CTX_COMMA
                     stack.s1.de);
  }
  PT_SPAWN(&rap_context->sub_pt,
           ecc_get_protothread(),
           ecc_generate_fhmqv_secret(rap_context->config->my_private_key,
                                     rap_context->my.ephemeral_private_key,
                                     rap_context->sm.public_key,
                                     rap_context->tee.ephemeral_public_key,
                                     stack.s1.de,
                                     stack.s1.de + (ECC_CURVE_P_256_SIZE / 2),
                                     stack.s2.sigma,
                                     &rap_context->result));
  if (rap_context->result) {
    coap_log_err("verify_tee_report: ecc_generate_fhmqv_secret failed\n");
    PT_EXIT(&rap_context->sub_pt);
  }
  memcpy(stack.s2.ikm,
         rap_context->config->my_public_key,
         2 * ECC_CURVE_P_256_SIZE);
  memcpy(stack.s2.ikm
         + 2 * ECC_CURVE_P_256_SIZE,
         rap_context->sm.public_key,
         sizeof(rap_context->sm.public_key));
  memcpy(stack.s2.ikm
         + 2 * ECC_CURVE_P_256_SIZE
         + sizeof(rap_context->sm.public_key),
         rap_context->my.ephemeral_public_key,
         sizeof(rap_context->my.ephemeral_public_key));
  memcpy(stack.s2.ikm
         + 2 * ECC_CURVE_P_256_SIZE
         + sizeof(rap_context->sm.public_key)
         + sizeof(rap_context->my.ephemeral_public_key),
         rap_context->tee.ephemeral_public_key,
         sizeof(rap_context->tee.ephemeral_public_key));
  sha_256_hkdf(
#if WITH_IRAP
      rap_context->config->expected_tee_hash, SHA_256_DIGEST_LENGTH,
#else /* ! WITH_IRAP */
      NULL, 0,
#endif /* ! WITH_IRAP */
      stack.s2.sigma, sizeof(stack.s2.sigma),
      stack.s2.ikm, sizeof(stack.s2.ikm),
      stack.s3.okm, sizeof(stack.s3.okm));

#if ! WITH_IRAP
  {
#if ! WITH_CONTIKI
    sha_256_hmac_context_t ctx;
#endif /* ! WITH_CONTIKI */

    sha_256_hmac_init(HASH_CTX_COMMA
                      stack.s3.okm,
                      ECC_CURVE_P_256_SIZE);
    sha_256_hmac_update(HASH_CTX_COMMA
                        rap_context->sm.public_key,
                        sizeof(rap_context->sm.public_key));
    sha_256_hmac_update(HASH_CTX_COMMA
                        rap_context->tee.ephemeral_public_key,
                        sizeof(rap_context->tee.ephemeral_public_key));
    sha_256_hmac_update(HASH_CTX_COMMA
                        rap_context->config->expected_tee_hash,
                        SHA_256_DIGEST_LENGTH);
    sha_256_hmac_finish(HASH_CTX_COMMA
                        stack.s3.fhmqv_mic);
  }
  if (memcmp(rap_context->msg.reg.tees_fhmqv_mic,
             stack.s3.fhmqv_mic,
             sizeof(rap_context->msg.reg.tees_fhmqv_mic))) {
    coap_log_err("verify_tee_report: received invalid TEE report\n");
    rap_context->result = -1;
    PT_EXIT(&rap_context->sub_pt);
  }

  {
#if ! WITH_CONTIKI
    sha_256_hmac_context_t ctx;
#endif /* ! WITH_CONTIKI */

    sha_256_hmac_init(HASH_CTX_COMMA
                      stack.s3.okm,
                      ECC_CURVE_P_256_SIZE);
    sha_256_hmac_update(HASH_CTX_COMMA
                        rap_context->config->my_public_key,
                        2 * ECC_CURVE_P_256_SIZE);
    sha_256_hmac_update(HASH_CTX_COMMA
                        rap_context->my.ephemeral_public_key,
                        sizeof(rap_context->my.ephemeral_public_key));
    sha_256_hmac_finish(HASH_CTX_COMMA
                        stack.s3.fhmqv_mic);
  }
  memcpy(clients_fhmqv_mic, stack.s3.fhmqv_mic, COAP_RAP_FHMQV_MIC_SIZE);
#endif /* ! WITH_IRAP */

  memcpy(secret, stack.s3.okm + ECC_CURVE_P_256_SIZE, ECC_CURVE_P_256_SIZE);
#else /* ! WITH_TRAP */
  union {
    uint8_t tee_report_hash[SHA_256_DIGEST_LENGTH];
    uint8_t tees_ephemeral_public_key[ECC_CURVE_P_256_SIZE * 2];
    uint8_t shared_secret[ECC_CURVE_P_256_SIZE];
  } stack;

  /* verify TEE report */
  {
#if ! WITH_CONTIKI
    sha_256_context_t ctx;
#endif /* ! WITH_CONTIKI */

    SHA_256.init(HASH_CTX);
    SHA_256.update(HASH_CTX_COMMA
                   rap_context->config->expected_tee_hash,
                   SHA_256_DIGEST_LENGTH);
    SHA_256.update(HASH_CTX_COMMA
                   rap_context->my.ephemeral_public_key_compressed,
                   sizeof(rap_context->my.ephemeral_public_key_compressed));
    SHA_256.update(HASH_CTX_COMMA
                   rap_context->tee.ephemeral_public_key_compressed,
                   sizeof(rap_context->tee.ephemeral_public_key_compressed));
    SHA_256.finalize(HASH_CTX_COMMA
                     stack.tee_report_hash);
  }
  PT_SPAWN(&rap_context->sub_pt,
           ecc_get_protothread(),
           ecc_verify(rap_context->msg.reg.sms_signature,
                      stack.tee_report_hash,
                      sms_public_key,
                      &rap_context->result));
  if (rap_context->result) {
    coap_log_err("verify_tee_report: received invalid TEE report\n");
    PT_EXIT(&rap_context->sub_pt);
  }

  /* decompress TEE's ephemeral public key */
  PT_SPAWN(&rap_context->sub_pt,
           ecc_get_protothread(),
           ecc_decompress_public_key(
               rap_context->tee.ephemeral_public_key_compressed,
               stack.tees_ephemeral_public_key,
               &rap_context->result));
  if (rap_context->result) {
    coap_log_err("verify_tee_report: "
                 "decompression of TEE's ephemeral public key failed\n");
    PT_EXIT(&rap_context->sub_pt);
  }

  /* generate shared secret */
  PT_SPAWN(&rap_context->sub_pt,
           ecc_get_protothread(),
           ecc_generate_shared_secret(stack.tees_ephemeral_public_key,
                                      rap_context->my.ephemeral_private_key,
                                      stack.shared_secret,
                                      &rap_context->result));
  if (rap_context->result) {
    coap_log_err("verify_tee_report: ecc_generate_shared_secret failed\n");
    PT_EXIT(&rap_context->sub_pt);
  }

  /* derive secret */
  sha_256_hkdf(rap_context->my.ephemeral_public_key_compressed,
               sizeof(rap_context->my.ephemeral_public_key_compressed),
               stack.shared_secret, sizeof(stack.shared_secret),
               NULL, 0,
               secret, ECC_CURVE_P_256_SIZE);
#endif /* ! WITH_TRAP */

  PT_END(&rap_context->sub_pt);
}

static void
on_timeout(coap_session_t *session,
           const coap_pdu_t *sent,
           const coap_nack_reason_t reason,
           const coap_mid_t mid) {
  (void)sent;
  (void)reason;
  (void)mid;
  /* TODO continue retransmitting upon receiving RSTs or erroneous messages */
  assert(session->rap_context);
  coap_log_err("on_timeout\n");
  session->rap_context->result = -1;
  session->rap_context->config->resume();
}

static int
init_oscore_ng_session(coap_session_t *session,
                       const coap_bin_const_t *recipient_id) {
  if (!coap_oscore_ng_init_client_session(session, recipient_id, 0)) {
    coap_log_err("init_oscore_ng_session: "
                 "coap_oscore_ng_init_client_session failed\n");
    return 0;
  }

  {
    oscore_ng_id_context_t id_context;

    id_context.len = ID_CONTEXT_SIZE;
#if WITH_TRAP
    memcpy(id_context.u8,
           session->rap_context->my.ephemeral_public_key,
           ID_CONTEXT_SIZE);
#else /* ! WITH_TRAP */
    memcpy(id_context.u8,
           session->rap_context->my.ephemeral_public_key_compressed + 1,
           ID_CONTEXT_SIZE);
#endif /* ! WITH_TRAP */
    /*
     * The subsequent request contains the full ID Context in the kid context
     * field. This allows the server to look up the right session.
     */
    oscore_ng_set_id_context(session->oscore_ng_context, &id_context, true);
  }

#if WITH_IRAP
  {
    static const coap_bin_const_t empty_token = { 0, NULL };

    if (!oscore_ng_unsecure(
            session->oscore_ng_context,
            COAP_MESSAGE_ACK,
            &empty_token,
            &session->rap_context->msg.reg.option_data,
            session->rap_context->msg.reg.payload.oscore_ng_mic,
            sizeof(session->rap_context->msg.reg.payload.oscore_ng_mic),
            false,
            session->rap_context->msg.reg.rx_timestamp)) {
      coap_oscore_ng_clear_context(session->oscore_ng_context);
      session->oscore_ng_context = NULL;
      coap_log_err("init_oscore_ng_session: oscore_ng_unsecure failed\n");
      return 0;
    }
  }
#endif /* WITH_IRAP */
  return 1;
}
#else /* ! COAP_RAP_SUPPORT || ! COAP_CLIENT_SUPPORT */
coap_rap_result_t
coap_rap_initiate(coap_session_t *session,
                  const coap_rap_config_t *config
#if WITH_TRAP && ! WITH_IRAP
                  , uint8_t clients_fhmqv_mic[COAP_RAP_FHMQV_MIC_SIZE]
#endif /* WITH_TRAP && ! WITH_IRAP */
                 ) {
  (void)session;
  (void)config;
#if WITH_TRAP && ! WITH_IRAP
  (void)clients_fhmqv_mic;
#endif /* WITH_TRAP && ! WITH_IRAP */
  return COAP_RAP_RESULT_EXITED;
}
#endif /* ! COAP_RAP_SUPPORT || ! COAP_CLIENT_SUPPORT */
