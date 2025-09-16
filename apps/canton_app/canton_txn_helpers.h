/**
 * @file    canton_txn_helpers.h
 * @author  Cypherock X1 Team
 * @brief   Header for canton transaction helpers
 *
 * @copyright Copyright (c) 2023 HODL TECH PTE LTD
 * <br/> You may obtain a copy of license at <a href="https://mitcc.org/"
 * target=_blank>https://mitcc.org/</a>
 */
#ifndef CANTON_TXN_HELPERS
#define CANTON_TXN_HELPERS

/*****************************************************************************
 * INCLUDES
 *****************************************************************************/

#include <stdbool.h>
#include <stdint.h>

#include "canton_context.h"

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
 * @brief Parse byte array of unsigned txn for canton
 *
 * @param byte_array[in] Reference to buffer with raw unsigned transaction
 * @param byte_array_size[in] Size of byte array
 * @param utxn[out] Reference to instance of @ref canton_unsigned_txn which will
 * be populated
 */
bool canton_parse_transaction(const uint8_t *byte_array,
                              uint16_t byte_array_size,
                              canton_unsigned_txn *utxn);

#endif
