/*
 * coap_rap_internal.h -- remote attestation and key exchange
 *
 * Copyright (C) 2021-2023 Uppsala universitet
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_rap_internal.h
 * @brief remote attestation and key exchange
 */

#ifndef COAP_RAP_INTERNAL_H_
#define COAP_RAP_INTERNAL_H_

/**
 * @ingroup internal_api
 * @addtogroup oscore_ng_internal
 * @{
 */

#include <stdint.h>
#include <stdlib.h>

#define COAP_RAP_MAX_COOKIE_SIZE (8)
#define COAP_RAP_SIGNATURE_SIZE (ECC_CURVE_P_256_SIZE * 2)
#define COAP_RAP_MAX_REPORT_SIZE \
  (1 /* compression information */ \
   + ECC_CURVE_P_256_SIZE /* SM's public key */ \
   + COAP_RAP_SIGNATURE_SIZE /* signature of SM report */ \
   + ECC_CURVE_P_256_SIZE /* enclave's ephemeral public key */ \
   + (WITH_TRAP \
   ? COAP_RAP_FHMQV_MIC_SIZE /* truncated FHMQV MIC */ \
   : COAP_RAP_SIGNATURE_SIZE /* signature of enclave report */))

struct coap_rap_context_t {
  const coap_rap_config_t *config;
  int result;
  struct pt sub_pt;

  struct {
    uint8_t ephemeral_private_key[ECC_CURVE_P_256_SIZE];
#if WITH_TRAP
    uint8_t ephemeral_public_key[ECC_CURVE_P_256_SIZE * 2];
#else /* ! WITH_TRAP */
    uint8_t ephemeral_public_key_compressed[1 + ECC_CURVE_P_256_SIZE];
#endif /* ! WITH_TRAP */
  } my;

  union {
#if WITH_TRAP
    uint8_t ephemeral_public_key[ECC_CURVE_P_256_SIZE * 2];
#endif /* WITH_TRAP */
    uint8_t ephemeral_public_key_compressed[1 + ECC_CURVE_P_256_SIZE];
  } tee;

  union {
#if WITH_TRAP
    uint8_t public_key[ECC_CURVE_P_256_SIZE * 2];
#endif /* WITH_TRAP */
    uint8_t public_key_compressed[1 + ECC_CURVE_P_256_SIZE];
  } sm;

  union {
    struct {
      uint8_t cookie[COAP_RAP_MAX_COOKIE_SIZE];
      size_t cookie_size;
    } kno;

    struct {
      uint8_t bootloaders_signature[COAP_RAP_SIGNATURE_SIZE];
#if WITH_TRAP
      uint8_t tees_fhmqv_mic[COAP_RAP_FHMQV_MIC_SIZE];
#else /* ! WITH_TRAP */
      uint8_t sms_signature[COAP_RAP_SIGNATURE_SIZE];
#endif /* ! WITH_TRAP */
    } reg;
  } msg;
};

extern const char knock_path[];
extern const size_t knock_path_length;
extern const char register_path[];
extern const size_t register_path_length;

/** @} */

#endif /* COAP_RAP_INTERNAL_H_ */
