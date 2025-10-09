/**
 * @file    canton_txn_encoding.c
 * @author  Cypherock X1 Team
 * @brief   Utilities specific to Canton chains
 * @copyright Copyright (c) 2024 HODL TECH PTE LTD
 * <br/> You may obtain a copy of license at <a href="https://mitcc.org/"
 *target=_blank>https://mitcc.org/</a>
 *
 ******************************************************************************
 * @attention
 *
 * (c) Copyright 2024 by HODL TECH PTE LTD
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject
 * to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR
 * ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 *
 * "Commons Clause" License Condition v1.0
 *
 * The Software is provided to you by the Licensor under the License,
 * as defined below, subject to the following condition.
 *
 * Without limiting other conditions in the License, the grant of
 * rights under the License will not include, and the License does not
 * grant to you, the right to Sell the Software.
 *
 * For purposes of the foregoing, "Sell" means practicing any or all
 * of the rights granted to you under the License to provide to third
 * parties, for a fee or other consideration (including without
 * limitation fees for hosting or consulting/ support services related
 * to the Software), a product or service whose value derives, entirely
 * or substantially, from the functionality of the Software. Any license
 * notice or attribution required by the License must also include
 * this Commons Clause License Condition notice.
 *
 * Software: All X1Wallet associated files.
 * License: MIT
 * Licensor: HODL TECH PTE LTD
 *
 ******************************************************************************
 */

/*****************************************************************************
 * INCLUDES
 *****************************************************************************/

#include "canton_txn_encoding.h"

#include <stddef.h>

#include "canton_api.h"
#include "canton_context.h"
#include "coin_utils.h"

/*****************************************************************************
 * EXTERN VARIABLES
 *****************************************************************************/

/*****************************************************************************
 * PRIVATE MACROS AND DEFINES
 *****************************************************************************/

/*****************************************************************************
 * PRIVATE TYPEDEFS
 *****************************************************************************/

/*****************************************************************************
 * STATIC FUNCTION PROTOTYPES
 *****************************************************************************/

/*****************************************************************************
 * STATIC VARIABLES
 *****************************************************************************/

/*****************************************************************************
 * GLOBAL VARIABLES
 *****************************************************************************/

/*****************************************************************************
 * STATIC FUNCTIONS
 *****************************************************************************/

/*****************************************************************************
 * GLOBAL FUNCTIONS
 *****************************************************************************/

uint8_t *encode_canton_txn_node(const canton_daml_transaction_d_node_t *d_node,
                                size_t *out_len) {
  if (!d_node || !out_len) {
    return NULL;
  }

  return NULL;
}

uint8_t *encode_canton_metadata_input_contract(
    const canton_metadata_input_contract_t *input_contract,
    size_t *out_len) {
  if (!input_contract || !out_len) {
    return NULL;
  }

  return NULL;
}

bool parse_and_hash_canton_txn_node(const uint8_t *txn_serialized_node,
                                    uint32_t txn_node_size,
                                    canton_txn_node_hash_t *node_hash) {
  if (!txn_serialized_node || !txn_node_size || !node_hash) {
    return false;
  }

  // decode protobuf serialized node
  canton_daml_transaction_d_node_t decoded_d_node =
      CANTON_DAML_TRANSACTION_D_NODE_INIT_ZERO;
  if (!decode_canton_serialized_data(txn_serialized_node,
                                     txn_node_size,
                                     CANTON_DAML_TRANSACTION_D_NODE_FIELDS,
                                     &decoded_d_node)) {
    return false;
  }

  // validate and encode transaction node
  size_t node_out_len = 0;
  uint8_t *encoded_node =
      encode_canton_txn_node(&decoded_d_node, &node_out_len);

  if (!encoded_node) {
    return false;
  }

  // hash encoded node
  sha256_Raw(encoded_node, node_out_len, node_hash->hash);

  // copy node id
  node_hash->node_id = strtol(decoded_d_node.node_id, NULL, 10);

  // free encoded node
  free(encoded_node);

  return true;
}

bool parse_and_hash_canton_metadata_input_contract(
    const uint8_t *txn_serialized_input_contract,
    uint32_t txn_input_contract_size,
    canton_txn_input_contract_hash_t *input_contract_hash) {
  if (!txn_serialized_input_contract || !txn_input_contract_size ||
      !input_contract_hash) {
    return false;
  }

  // decode protobuf serialized input contract
  canton_metadata_input_contract_t decoded_input_contract =
      CANTON_METADATA_INPUT_CONTRACT_INIT_ZERO;
  if (!decode_canton_serialized_data(txn_serialized_input_contract,
                                     txn_input_contract_size,
                                     CANTON_METADATA_INPUT_CONTRACT_FIELDS,
                                     &decoded_input_contract)) {
    return false;
  }

  // validate and encode input contract
  size_t input_contract_out_len = 0;
  uint8_t *encoded_input_contract = encode_canton_metadata_input_contract(
      &decoded_input_contract, &input_contract_out_len);
  if (!encoded_input_contract) {
    return false;
  }

  // hash encoded input contract
  sha256_Raw(encoded_input_contract,
             input_contract_out_len,
             input_contract_hash->hash);

  // free encoded input contract
  free(encoded_input_contract);

  return true;
}

bool validate_and_encode_canton_unsigned_txn() {
  if (!canton_txn_context) {
    return false;
  }
  return true;
}