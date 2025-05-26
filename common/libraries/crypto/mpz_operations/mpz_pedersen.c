/**
 * @author  Cypherock X1 Team
 * @brief   pedersen hashing alogrithms
 * @copyright Copyright (c) 2023 HODL TECH PTE LTD
 * <br/> You may obtain a copy of license at <a href="https://mitcc.org/"
 *target=_blank>https://mitcc.org/</a>
 *
 ******************************************************************************
 * @attention
 *
 * (c) Copyright 2023 by HODL TECH PTE LTD
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

// Standard headers can be outside the guard if they are truly universal
#include <stdint.h>

// Conditionally compile the entire StarkNet-specific content of this file
#ifndef BTC_ONLY_BUILD

#include "starknet_pedersen.h" // Self-header, implies its declarations also need guarding

#include <error.pb.h> // If used by the StarkNet code

#include "coin_utils.h"       // If used by StarkNet code
#include "mini-gmp-helpers.h" // For mpz functions, used by StarkNet code
// Specific StarkNet headers that define types like mpz_curve_point (if specific version),
// stark_curve, starknet_pedersen_points, LOW_PART_BITS, etc.
#include "starknet_api.h"
#include "starknet_context.h"
#include "starknet_crypto.h"
#include "starknet_helpers.h"
#include "mpz_ecdsa.h" // For mpz_curve_point type and ECC operations from mpz_ecdsa.c

/*****************************************************************************
 * EXTERN VARIABLES
 *****************************************************************************/
// extern const mpz_curve stark_curve; // Declaration likely in starknet_context.h
// extern const starknet_pedersen_points_t *starknet_pedersen_points; // Declaration likely in starknet_context.h

/*****************************************************************************
 * PRIVATE MACROS AND DEFINES
 *****************************************************************************/
#ifndef LOW_PART_BITS
#define LOW_PART_BITS 248 // Ensure this is defined, usually from a StarkNet context header
#endif

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
 * GLOBAL FUNCTIONS
 *****************************************************************************/

void process_single_element(mpz_t element,
                            mpz_curve_point *p1,
                            mpz_curve_point *p2,
                            mpz_curve_point *result) {
  ASSERT(stark_curve != NULL && p1 != NULL && p2 != NULL && result != NULL && element != NULL);
  ASSERT(mpz_cmp(element, stark_curve->prime) < 0);

  mpz_t low_part, high_nibble;
  mpz_init(low_part);
  mpz_init(high_nibble);

  mpz_t mask;
  mpz_init(mask);
  mpz_ui_pow_ui(mask, 2, 248);
  mpz_sub_ui(mask, mask, 1);

  mpz_and(low_part, element, mask);
  mpz_fdiv_q_2exp(high_nibble, element, LOW_PART_BITS);

  mpz_curve_point res1, res2_sum_intermediate;
  mpz_curve_point_init(&res1);
  mpz_curve_point_init(&res2_sum_intermediate);

  mpz_curve_point_multiply(stark_curve, low_part, p1, &res1);
  mpz_curve_point_multiply(stark_curve, high_nibble, p2, &res2_sum_intermediate);

  // Assuming mpz_curve_point_add(curve, P, Q_result) stores P + Q_original in Q_result
  // To get result = res1 + res2_sum_intermediate
  mpz_curve_point_copy(result, &res1); // result = res1
  mpz_curve_point_add(stark_curve, &res2_sum_intermediate, result); // result = result + res2_sum_intermediate

  mpz_clear(low_part);
  mpz_clear(high_nibble);
  mpz_clear(mask);

  mpz_curve_point_clear(&res1);
  mpz_curve_point_clear(&res2_sum_intermediate);
}

void pederson_hash(uint8_t *x, uint8_t *y, uint8_t size, uint8_t *hash) {
  ASSERT(NULL != x);
  ASSERT(NULL != y);
  ASSERT(0 < size);
  ASSERT(NULL != hash);

  mpz_t a, b;
  mpz_init(a);
  mpz_init(b);

  mpz_import(a, size, 1, 1, 1, 0, x);
  mpz_import(b, size, 1, 1, 1, 0, y);

  ASSERT(starknet_pedersen_points != NULL);

  mpz_curve_point HASH_SHIFT_POINT, P_1, P_2, P_3, P_4;
  mpz_curve_point_init(&HASH_SHIFT_POINT);
  mpz_curve_point_init(&P_1);
  mpz_curve_point_init(&P_2);
  mpz_curve_point_init(&P_3);
  mpz_curve_point_init(&P_4);

  mpz_curve_point_copy(&HASH_SHIFT_POINT, &starknet_pedersen_points->P[0]);
  mpz_curve_point_copy(&P_1, &starknet_pedersen_points->P[1]);
  mpz_curve_point_copy(&P_2, &starknet_pedersen_points->P[2]);
  mpz_curve_point_copy(&P_3, &starknet_pedersen_points->P[3]);
  mpz_curve_point_copy(&P_4, &starknet_pedersen_points->P[4]);

  mpz_curve_point x_part, y_part, final_hash_point;
  mpz_curve_point_init(&x_part);
  mpz_curve_point_init(&y_part);
  mpz_curve_point_init(&final_hash_point);

  process_single_element(a, &P_1, &P_2, &x_part);
  process_single_element(b, &P_3, &P_4, &y_part);

  // hash = shift_point + x_part + y_part
  mpz_curve_point_copy(&final_hash_point, &HASH_SHIFT_POINT);             // final_hash_point = HASH_SHIFT_POINT
  mpz_curve_point_add(stark_curve, &x_part, &final_hash_point);         // final_hash_point += x_part
  mpz_curve_point_add(stark_curve, &y_part, &final_hash_point);         // final_hash_point += y_part

  memzero(hash, 32); // Assuming memzero is available
  mpz_to_byte_array(final_hash_point.x, hash, 32); // Assuming mpz_to_byte_array is available

  mpz_curve_point_clear(&x_part);
  mpz_curve_point_clear(&y_part);
  mpz_curve_point_clear(&final_hash_point);

  mpz_clear(a);
  mpz_clear(b);
  // mpz_clear(result); // 'result' mpz_t was removed as it was unused

  mpz_curve_point_clear(&HASH_SHIFT_POINT);
  mpz_curve_point_clear(&P_1);
  mpz_curve_point_clear(&P_2);
  mpz_curve_point_clear(&P_3);
  mpz_curve_point_clear(&P_4);
}

#endif // !BTC_ONLY_BUILD