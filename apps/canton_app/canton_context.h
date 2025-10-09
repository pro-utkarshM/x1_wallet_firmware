/**
 * @file    canton_context.h
 * @author  Cypherock X1 Team
 * @brief   Header file defining typedefs and MACROS for the canton app
 *
 * @copyright Copyright (c) 2023 HODL TECH PTE LTD
 * <br/> You may obtain a copy of license at <a href="https://mitcc.org/"
 * target=_blank>https://mitcc.org/</a>
 */
#ifndef CANTON_CONTEXT_H
#define CANTON_CONTEXT_H

/*****************************************************************************
 * INCLUDES
 *****************************************************************************/

/*****************************************************************************
 * MACROS AND DEFINES
 *****************************************************************************/

#include <stdint.h>
#include "canton/sign_txn.pb.h"
#define CANTON_NAME "CANTON"
#define CANTON_LUNIT "CC"

#define CANTON_IMPLICIT_ACCOUNT_DEPTH 5

#define CANTON_PURPOSE_INDEX 0x8000002C    // 44'
#define CANTON_COIN_INDEX 0x80001a6f       // 6767'
#define CANTON_ACCOUNT_INDEX 0x80000000    // 0'
#define CANTON_CHANGE_INDEX 0x80000000     // 0'

#define CANTON_PUB_KEY_SIZE 32
#define CANTON_HASH_PURPOSE_SIZE 4
#define CANTON_FINGERPRINT_PREFIX_SIZE 2
#define CANTON_FINGERPRINT_SIZE                                                \
  CANTON_FINGERPRINT_PREFIX_SIZE + SHA256_DIGEST_LENGTH
#define CANTON_PARTY_HINT_SIZE 5
#define CANTON_FINGERPRINT_STR_SIZE ((CANTON_FINGERPRINT_SIZE) * 2) + 1
#define CANTON_PARTY_HINT_STR_SIZE (CANTON_PARTY_HINT_SIZE * 2) + 1
#define CANTON_PARTY_ID_SEPARATOR_SIZE 3 /*for ::*/
#define CANTON_PARTY_ID_SIZE                                                   \
  CANTON_PARTY_HINT_STR_SIZE + CANTON_PARTY_ID_SEPARATOR_SIZE +                \
      CANTON_FINGERPRINT_STR_SIZE - 2 /*for null byte*/

/*****************************************************************************
 * TYPEDEFS
 *****************************************************************************/

typedef struct {
} canton_config_t;

typedef canton_sign_txn_node_seed_node_seed_t canton_txn_node_seed_t;

typedef struct {
  char node_id;
  uint8_t hash[32];
} canton_txn_node_hash_t;

typedef struct {
  char receiver_party_id[255];
  uint64_t amount;
  // TODO: add more fields

} canton_txn_user_relevant_info_t;

typedef struct {
  uint8_t hash[32];
} canton_txn_input_contract_hash_t;

typedef struct {
  // TODO: canton fields
  canton_sign_txn_transaction_metadata_t txn_meta;
  canton_sign_txn_canton_metadata_t canton_meta;
  canton_txn_node_seed_t *txn_node_seeds;
  canton_txn_node_hash_t *txn_node_hashes;
  canton_txn_input_contract_hash_t *input_contract_hashes;
  canton_txn_user_relevant_info_t *txn_user_relevant_info;
} canton_unsigned_txn;

typedef struct {
  uint8_t hash[32];
  // TODO: canton party txn field
} canton_party_txn;

typedef struct {
  // TODO: canton fields
} canton_unsigned_topology_txn;

/*****************************************************************************
 * EXPORTED VARIABLES
 *****************************************************************************/

/*****************************************************************************
 * GLOBAL FUNCTION PROTOTYPES
 *****************************************************************************/

#endif
