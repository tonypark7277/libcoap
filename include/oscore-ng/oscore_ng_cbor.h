/*
 * Copyright (c) 2018, SICS, RISE AB
 * Copyright (c) 2023, Uppsala universitet
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
 *
 */

/**
 * @file oscore_ng_cbor.h
 * @brief CBOR helpers
 */

#ifndef OSCORE_NG_CBOR_H_
#define OSCORE_NG_CBOR_H_

/**
 * @ingroup internal_api
 * @defgroup oscore_ng_cbor OSCORE-NG CBOR Support
 * Internal API for CBOR
 * @{
 */

#include <stddef.h>
#include <stdint.h>

#ifndef CBOR_MAX_NESTING
/**
 * Defines how many arrays and maps can be open simultaneously while writing.
 */
#define CBOR_MAX_NESTING (8)
#endif /* CBOR_MAX_NESTING */

#define CBOR_UNSIGNED_SIZE(uint) ((uint) < CBOR_SIZE_1 \
                                  ? 1 \
                                  : ((uint) <= UINT8_MAX \
                                     ? 1 + 1 \
                                     : ((uint) <= UINT16_MAX \
                                        ? 1 + 2 \
                                        : ((uint) <= UINT32_MAX \
                                           ? 1 + 4 \
                                           : 1 + 8))))
#define CBOR_BYTE_STRING_SIZE(bytes) (CBOR_UNSIGNED_SIZE(bytes) + (bytes))

/**
 * Enumeration of major types.
 */
typedef enum cbor_major_type_t {
  CBOR_MAJOR_TYPE_NONE = -1,
  CBOR_MAJOR_TYPE_UNSIGNED = 0x00,
  CBOR_MAJOR_TYPE_BYTE_STRING = 0x40,
  CBOR_MAJOR_TYPE_TEXT_STRING = 0x60,
  CBOR_MAJOR_TYPE_ARRAY = 0x80,
  CBOR_MAJOR_TYPE_MAP = 0xA0,
  CBOR_MAJOR_TYPE_SIMPLE = 0xE0,
} cbor_major_type_t;

/**
 * Enumeration of simple values.
 */
typedef enum cbor_simple_value_t {
  CBOR_SIMPLE_VALUE_NONE = -1,
  CBOR_SIMPLE_VALUE_FALSE = 0xF4,
  CBOR_SIMPLE_VALUE_TRUE = 0xF5,
  CBOR_SIMPLE_VALUE_NULL = 0xF6,
  CBOR_SIMPLE_VALUE_UNDEFINED = 0xF7,
} cbor_simple_value_t;

/**
 * Enumeration of size information in various major types.
 */
typedef enum cbor_size_t {
  CBOR_SIZE_NONE = -1, /**< error condition */
  CBOR_SIZE_1 = 0x18,  /**< 1 byte */
  CBOR_SIZE_2 = 0x19,  /**< 2 bytes */
  CBOR_SIZE_4 = 0x1A,  /**< 4 bytes */
  CBOR_SIZE_8 = 0x1B,  /**< 8 bytes */
} cbor_size_t;

/**
 * Structure of a nesting record.
 */
typedef struct cbor_nesting_record_t {
  uint8_t *start;
  size_t objects;
} cbor_nesting_record_t;

/**
 * Structure of the internal state of a CBOR writer.
 */
typedef struct cbor_writer_state_t {
  const uint8_t *buffer_head;
  uint8_t *buffer;
  size_t buffer_size;
  size_t nesting_depth;
  cbor_nesting_record_t records[CBOR_MAX_NESTING];
} cbor_writer_state_t;

/**
 * Prepares for writing CBOR output.
 *
 * @param state       State of the CBOR writer.
 * @param buffer      Buffer for holding CBOR output.
 * @param buffer_size Size of @p buffer in bytes.
 */
void cbor_init_writer(cbor_writer_state_t *state,
                      uint8_t *buffer, size_t buffer_size);

/**
 * Finishes writing CBOR output.
 *
 * @param state State of the CBOR writer.
 *
 * @return      Size of the CBOR output or @c 0 on error.
 */
size_t cbor_end_writer(cbor_writer_state_t *state);

/**
 * Marks the CBOR output as erroneous.
 *
 * @param state State of the CBOR writer.
 */
void cbor_break_writer(cbor_writer_state_t *state);

/**
 * Appends an arbitrary CBOR object.
 *
 * @param state       State of the CBOR writer.
 * @param object      Location of the CBOR object.
 * @param object_size Size of @p object in bytes.
 */
void cbor_write_object(cbor_writer_state_t *state,
                       const void *object, size_t object_size);

/**
 * Appends an unsigned integer.
 *
 * @param state State of the CBOR writer.
 * @param value Unsigned integer.
 */
void cbor_write_unsigned(cbor_writer_state_t *state, uint64_t value);

/**
 * Appends a byte string.
 *
 * @param state     State of the CBOR writer.
 * @param data      The byte string.
 * @param data_size Size of @p data in bytes.
 */
void cbor_write_data(cbor_writer_state_t *state,
                     const uint8_t *data, size_t data_size);

/**
 * Appends a text string.
 *
 * @param state     State of the CBOR writer.
 * @param text      The text string.
 * @param text_size Number of characters in @p text.
 */
void cbor_write_text(cbor_writer_state_t *state,
                     const char *text, size_t text_size);

/**
 * Appends the simple value @c null.
 *
 * @param state State of the CBOR writer.
 */
void cbor_write_null(cbor_writer_state_t *state);

/**
 * Appends the simple value @c undefined.
 *
 * @param state State of the CBOR writer.
 */
void cbor_write_undefined(cbor_writer_state_t *state);

/**
 * Appends a boolean simple value.
 *
 * @param state   State of the CBOR writer.
 * @param boolean Value @c 1 means true, and @c 0 means false.
 */
void cbor_write_bool(cbor_writer_state_t *state, int boolean);

/**
 * Encloses subsequent CBOR objects in a byte string.
 *
 * @param state State of the CBOR writer.
 */
void cbor_open_data(cbor_writer_state_t *state);

/**
 * Stops enclosing subsequent CBOR objects in the innermost byte string.
 *
 * @param state State of the CBOR writer.
 */
void cbor_close_data(cbor_writer_state_t *state);

/**
 * Adds subsequent CBOR objects to an array.
 *
 * @param state State of the CBOR writer.
 */
void cbor_open_array(cbor_writer_state_t *state);

/**
 * Stops adding subsequent CBOR objects to the innermost array.
 *
 * @param state State of the CBOR writer.
 */
void cbor_close_array(cbor_writer_state_t *state);

/**
 * Adds subsequent entries to a map.
 *
 * @param state State of the CBOR writer.
 */
void cbor_open_map(cbor_writer_state_t *state);

/**
 * Stops adding subsequent entries to the innermost map.
 *
 * @param state State of the CBOR writer.
 */
void cbor_close_map(cbor_writer_state_t *state);

/** @} */

#endif /* OSCORE_NG_CBOR_H_ */
