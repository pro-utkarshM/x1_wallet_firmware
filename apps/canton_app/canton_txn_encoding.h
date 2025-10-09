/**
 * @file    canton_txn_encoding.h
 * @author  Cypherock X1 Team
 * @brief   Utilities api definitions for CANTON chains
 * @copyright Copyright (c) 2024 HODL TECH PTE LTD
 * <br/> You may obtain a copy of license at <a href="https://mitcc.org/"
 * target=_blank>https://mitcc.org/</a>
 */
#ifndef CANTON_TXN_ENCODING_H
#define CANTON_TXN_ENCODING_H

/*****************************************************************************
 * INCLUDES
 *****************************************************************************/

#include <stdbool.h>
#include <stdint.h>

#include "canton/canton_prepared_transaction.pb.h"
#include "canton_context.h"
#include "canton_priv.h"

/*****************************************************************************
 * MACROS AND DEFINES
 *****************************************************************************/

/*****************************************************************************
 * TYPEDEFS
 *****************************************************************************/

/*****************************************************************************
 * EXPORTED VARIABLES
 *****************************************************************************/

/*****************************************************************************
 * GLOBAL FUNCTION PROTOTYPES
 *****************************************************************************/

/**
 * @brief Parses, validates, encodes and hashes a canton transaction node.
 * @details The function will parse the transaction node, validate it, encode it
 * and hash it.
 *
 * @param[in] txn_serialized_node The serialized transaction node
 * @param[in] txn_node_size The size of the serialized transaction node
 * @param[out] node_hash The node hash of the encoded, validated transaction
 * node
 * @return bool Indicates if the transaction node was parsed, validated, encoded
 * and hashed successfully
 */
bool parse_and_hash_canton_txn_node(const uint8_t *txn_serialized_node,
                                    uint32_t txn_node_size,
                                    canton_txn_node_hash_t *node_hash);

/**
 * @brief Parses, validates, encodes and hashes a canton metadata input
 * contract.
 * @details The function will parse the input contract, validate it, encode it
 * and hash it.
 *
 * @param[in] txn_serialized_input_contract The serialized input contract
 * @param[in] txn_input_contract_size The size of the serialized input contract
 * @param[out] input_contract_hash The input contract hash of the encoded,
 * validated input contract
 * @return bool Indicates if the input contract was parsed, validated, encoded
 * and hashed successfully
 */
bool parse_and_hash_canton_metadata_input_contract(
    const uint8_t *txn_serialized_input_contract,
    uint32_t txn_input_contract_size,
    canton_txn_input_contract_hash_t *input_contract_hash);

/**
 * @brief Validates and encodes a canton unsigned transaction and stores it in
 * canton_txn_context.
 * @details The function takes the canton unsigned transaction from
 * canton_txn_context and validates and encodes it. It stores the encoded
 * transaction in the canton_txn_context.
 *
 * @return bool Indicates if the unsigned transaction was validated, encoded and
 * stored successfully
 */
bool validate_and_encode_canton_unsigned_txn();

#endif    // CANTON_TXN_ENCODING_H