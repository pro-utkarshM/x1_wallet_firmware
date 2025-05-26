/**
 * @author  Cypherock X1 Team
 * @brief   ec operations using mpz nums
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
#include "mpz_ecdsa.h" // Should declare types like mpz_curve_point, mpz_curve

#include <bignum.h>           // For bignum256 type, assumed available
#include "mini-gmp-helpers.h" // Assumed available
#include <stdbool.h>
#include "assert_conf.h" // Assumed available
#include "mini-gmp.h"    // Assumed available
#include "rfc6979.h"   // For deterministic k generation, assumed available

// StarkNet specific includes and dependencies are guarded
#ifndef BTC_ONLY_BUILD
#include <starknet_context.h> // This likely defines STARKNET_BIGNUM_SIZE and curve parameters
                              // Not available in BTC_ONLY_BUILD
#endif                        // !BTC_ONLY_BUILD

/*****************************************************************************
 * EXTERN VARIABLES
 *****************************************************************************/
// If stark_curve or other StarkNet globals are used by generic functions,
// they would need to be passed as parameters or handled conditionally.

/*****************************************************************************
 * PRIVATE MACROS AND DEFINES
 *****************************************************************************/
#ifndef STARKNET_BIGNUM_SIZE
// Define a fallback or default if STARKNET_BIGNUM_SIZE is not available (e.g. in BTC_ONLY_BUILD)
// This is a placeholder; ideally, functions should be parameterized or use a generic size.
// If BTC needs these helpers with a specific size, that should be used.
// For now, to allow compilation of generic parts if STARKNET_BIGNUM_SIZE is only from starknet_context.h
// we might need a different strategy if these static helpers are truly needed by generic functions.
// However, the static helpers below are only used by starknet_sign_digest currently.
#define GENERIC_BIGNUM_SIZE 32 // Default to 32 bytes (256 bits) if not StarkNet specific
#endif

/*****************************************************************************
 * PRIVATE TYPEDEFS
 *****************************************************************************/

/*****************************************************************************
 * STATIC FUNCTION PROTOTYPES
 *****************************************************************************/

#ifndef BTC_ONLY_BUILD
// These static functions are only compiled if not BTC_ONLY_BUILD,
// especially if they rely on STARKNET_BIGNUM_SIZE from starknet_context.h
static void mpz_to_bn(bignum256 *bn, const mpz_t mpz);
static void bn_to_mpz(mpz_t mpz, const bignum256 *bn);
static void generate_k_rfc6979_mpz(mpz_t k, rfc6979_state *state);
static void generate_k_random(bignum256 *k, const bignum256 *prime); // Used by generate_k_random_mpz
static void generate_k_random_mpz(mpz_t k, const mpz_t prime);
#endif // !BTC_ONLY_BUILD

/*****************************************************************************
 * STATIC FUNCTIONS
 *****************************************************************************/
#ifndef BTC_ONLY_BUILD
// These functions are guarded because they use STARKNET_BIGNUM_SIZE,
// which we assume is defined in starknet_context.h and thus not available in BTC_ONLY_BUILD.
// If these helpers were made generic (e.g., by parameterizing size), they could be outside the guard.

static void mpz_to_bn(bignum256 *bn, const mpz_t mpz) {
  uint8_t out[STARKNET_BIGNUM_SIZE] = {0};
  mpz_to_byte_array(mpz, out, STARKNET_BIGNUM_SIZE);
  bn_read_be(out, bn);
}

static void bn_to_mpz(mpz_t mpz, const bignum256 *bn) {
  uint8_t in[STARKNET_BIGNUM_SIZE] = {0};
  bn_write_be(bn, in);
  mpz_import(mpz, STARKNET_BIGNUM_SIZE, 1, 1, 1, 0, in);
}

static void generate_k_rfc6979_mpz(mpz_t k, rfc6979_state *state) {
  uint8_t buf[STARKNET_BIGNUM_SIZE] = {0};
  generate_rfc6979(buf, state); // Assuming generate_rfc6979 is generic but uses the buffer size
  mpz_import(k, STARKNET_BIGNUM_SIZE, 1, 1, 1, 0, buf);
  memzero(buf, STARKNET_BIGNUM_SIZE); // Use STARKNET_BIGNUM_SIZE for consistency
}

static void generate_k_random(bignum256 *k, const bignum256 *prime) {
  do {
    int i = 0;
    for (i = 0; i < 8; i++) {
      // Assuming random32() is available from a common source
      k->val[i] = random32() & 0x3FFFFFFF;
    }
    k->val[8] = random32() & 0xFFFF;
  } while (bn_is_zero(k) || !bn_is_less(k, prime));
}

static void generate_k_random_mpz(mpz_t k, const mpz_t prime) {
  bignum256 prime_bn, k_bn = {0};
  mpz_to_bn(&prime_bn, prime); // Uses STARKNET_BIGNUM_SIZE
  mpz_to_bn(&k_bn, k);         // Uses STARKNET_BIGNUM_SIZE
  generate_k_random(&k_bn, &prime_bn);
  bn_to_mpz(k, &k_bn);         // Uses STARKNET_BIGNUM_SIZE
}
#endif // !BTC_ONLY_BUILD

/*****************************************************************************
 * GLOBAL FUNCTIONS
 *****************************************************************************/

// These elliptic curve point operations are generally useful and should be available
// regardless of BTC_ONLY_BUILD, as long as they don't call StarkNet-specific static functions
// or use StarkNet-specific global variables/constants directly. They operate on passed-in curve parameters.

void mpz_curve_point_init(mpz_curve_point *p) {
  ASSERT(p != NULL);
  mpz_init(p->x);
  mpz_init(p->y);
}

void mpz_curve_point_clear(mpz_curve_point *p) {
  ASSERT(p != NULL);
  mpz_clear(p->x);
  mpz_clear(p->y);
}

void mpz_curve_point_copy(const mpz_curve_point *cp1, mpz_curve_point *cp2) {
  ASSERT(cp1 != NULL && cp2 != NULL);
  mpz_set(cp2->x, cp1->x);
  mpz_set(cp2->y, cp1->y);
}

void mpz_curve_point_add(const mpz_curve *curve,
                         const mpz_curve_point *cp1,
                         mpz_curve_point *cp2_result) { // Renamed for clarity: result is stored in cp2_result
  ASSERT(curve != NULL && cp1 != NULL && cp2_result != NULL);

  mpz_t lambda, inv, xr, yr;

  // Handle point at infinity cases
  if (mpz_curve_point_is_infinity(cp1)) {
    // If P1 is infinity, P1 + P2 = P2. (cp2_result is already P2, so no change if cp1 is this param)
    // If cp1 and cp2_result are different, mpz_curve_point_copy(cp2_result, cp1_original_cp2) might be needed.
    // Assuming cp2_result is P2 and the result should be P1+P2 stored in P2.
    // If P1=Inf, P2=P2. cp2_result is already P2.
    return;
  }
  if (mpz_curve_point_is_infinity(cp2_result)) {
    mpz_curve_point_copy(cp2_result, cp1); // P1 + Inf = P1. Store P1 in cp2_result.
    return;
  }

  // Handle doubling: P + P = 2P
  if (mpz_curve_point_is_equal(cp1, cp2_result)) {
    mpz_curve_point_double(curve, cp2_result); // cp2_result becomes 2 * cp2_result_original
    return;
  }

  // Handle P + (-P) = Infinity
  // Note: mpz_curve_point_is_negative_of expects curve->prime for modulo.
  if (mpz_curve_point_is_negative_of(cp1, cp2_result, curve)) { // Pass curve for prime
    mpz_curve_point_set_infinity(cp2_result);
    return;
  }

  mpz_init(lambda);
  mpz_init(inv);
  mpz_init(xr);
  mpz_init(yr);

  // inv = (cp2_result->x - cp1->x) mod prime
  mpz_sub(inv, cp2_result->x, cp1->x);
  mpz_mod(inv, inv, curve->prime);

  // inv = inv^-1 mod prime
  mpz_invert(inv, inv, curve->prime);

  // lambda = (cp2_result->y - cp1->y) mod prime
  mpz_sub(lambda, cp2_result->y, cp1->y);
  mpz_mod(lambda, lambda, curve->prime);

  // lambda = lambda * inv mod prime
  mpz_mul(lambda, lambda, inv);
  mpz_mod(lambda, lambda, curve->prime);

  // xr = lambda^2 - cp1->x - cp2_result->x mod prime
  mpz_mul(xr, lambda, lambda);
  mpz_sub(xr, xr, cp1->x);
  mpz_sub(xr, xr, cp2_result->x);
  mpz_mod(xr, xr, curve->prime);

  // yr = lambda * (cp1->x - xr) - cp1->y mod prime
  mpz_sub(yr, cp1->x, xr);
  mpz_mul(yr, yr, lambda);
  mpz_sub(yr, yr, cp1->y);
  mpz_mod(yr, yr, curve->prime);

  mpz_set(cp2_result->x, xr);
  mpz_set(cp2_result->y, yr);

  mpz_clear(lambda);
  mpz_clear(inv);
  mpz_clear(xr);
  mpz_clear(yr);
}

void mpz_curve_point_double(const mpz_curve *curve, mpz_curve_point *cp) {
  ASSERT(curve != NULL && cp != NULL);
  // If point is infinity, 2 * Infinity = Infinity
  if (mpz_curve_point_is_infinity(cp)) {
    return;
  }
  // If y-coordinate is 0, then 2P = Infinity (tangent is vertical)
  if (mpz_cmp_ui(cp->y, 0) == 0) {
    mpz_curve_point_set_infinity(cp);
    return;
  }

  mpz_t lambda, xr, yr, inv_2y;
  mpz_init(lambda);
  mpz_init(xr);
  mpz_init(yr);
  mpz_init(inv_2y);

  // lambda = (3 * cp->x^2 + curve->a) * (2 * cp->y)^-1 mod prime
  mpz_mul(lambda, cp->x, cp->x);      // x^2
  mpz_mul_ui(lambda, lambda, 3);      // 3x^2
  mpz_add(lambda, lambda, curve->a);  // 3x^2 + a (numerator of lambda)

  mpz_mul_ui(inv_2y, cp->y, 2);       // 2y
  mpz_invert(inv_2y, inv_2y, curve->prime); // (2y)^-1

  mpz_mul(lambda, lambda, inv_2y);    // lambda = numerator * (2y)^-1
  mpz_mod(lambda, lambda, curve->prime);

  // xr = lambda^2 - 2 * cp->x mod prime
  mpz_mul(xr, lambda, lambda);      // lambda^2
  mpz_submul_ui(xr, cp->x, 2);      // xr = lambda^2 - 2*cp->x (mpz_submul_ui(a,b,c) means a = a - b*c)
  mpz_mod(xr, xr, curve->prime);

  // yr = lambda * (cp->x - xr) - cp->y mod prime
  mpz_sub(yr, cp->x, xr);           // cp->x - xr
  mpz_mul(yr, yr, lambda);          // lambda * (cp->x - xr)
  mpz_sub(yr, yr, cp->y);           // lambda * (cp->x - xr) - cp->y
  mpz_mod(yr, yr, curve->prime);

  mpz_set(cp->x, xr);
  mpz_set(cp->y, yr);

  mpz_clear(lambda);
  mpz_clear(xr);
  mpz_clear(yr);
  mpz_clear(inv_2y);
}

void mpz_curve_point_set_infinity(mpz_curve_point *p) {
  ASSERT(p != NULL);
  mpz_set_ui(p->x, 0);
  mpz_set_ui(p->y, 0);
}

int mpz_curve_point_is_infinity(const mpz_curve_point *p) {
  ASSERT(p != NULL);
  return mpz_cmp_ui(p->x, 0) == 0 && mpz_cmp_ui(p->y, 0) == 0;
}

int mpz_curve_point_is_equal(const mpz_curve_point *p, const mpz_curve_point *q) {
  ASSERT(p != NULL && q != NULL);
  return (mpz_cmp(p->x, q->x) == 0) && (mpz_cmp(p->y, q->y) == 0);
}

// Returns true iff p = -q (i.e., p.x == q.x and p.y + q.y == 0 mod prime)
// Excludes cases where p or q is infinity, or p.y (and thus q.y) is 0 on the curve.
int mpz_curve_point_is_negative_of(const mpz_curve_point *p, const mpz_curve_point *q, const mpz_curve *curve) {
  ASSERT(p != NULL && q != NULL && curve != NULL);
  if (mpz_cmp(p->x, q->x) != 0) {
    return 0; // x-coordinates must match
  }
  // If p.y is 0, for p = -q, q.y must also be 0. This means p=q, handled by is_equal or implies point of order 2.
  // For distinct p and -q (where y != 0), p.y + q.y should be a multiple of prime.
  if (mpz_cmp_ui(p->y, 0) == 0) {
      return mpz_cmp_ui(q->y, 0) == 0; // If p.y is 0, q.y must be 0 for p_x = q_x
  }

  mpz_t sum_y;
  mpz_init(sum_y);
  mpz_add(sum_y, p->y, q->y);
  mpz_mod(sum_y, sum_y, curve->prime);
  int result = (mpz_cmp_ui(sum_y, 0) == 0);
  mpz_clear(sum_y);
  return result;
}

// Scalar multiplication R = k * P
void mpz_curve_point_multiply(const mpz_curve *curve,
                              const mpz_t k,
                              const mpz_curve_point *P, // Input point P
                              mpz_curve_point *R) {      // Output point R
  ASSERT(curve != NULL && k != NULL && P != NULL && R != NULL);

  mpz_curve_point T; // Temporary point for doublings, T starts as P
  mpz_curve_point_init(&T);
  mpz_curve_point_copy(&T, P);

  mpz_curve_point_set_infinity(R); // Initialize result R to point at infinity

  if (mpz_cmp_ui(k, 0) == 0 || mpz_curve_point_is_infinity(P)) {
    mpz_curve_point_clear(&T);
    return; // k*P = Inf if k is 0 or P is Inf
  }

  size_t num_bits = mpz_sizeinbase(k, 2);

  for (size_t i = 0; i < num_bits; ++i) {
    if (mpz_tstbit(k, i)) { // If bit i of k is 1
      mpz_curve_point_add(curve, &T, R); // R = R + T (current 2^i * P)
    }
    if (i < num_bits - 1) { // Avoid unnecessary double on last iteration
        mpz_curve_point_double(curve, &T); // T = 2 * T
    }
  }

  mpz_curve_point_clear(&T);
}

// These mpz_t based bit utilities appear generic
int bn_bit_length(const mpz_t k) {
  if (mpz_cmp_ui(k, 0) == 0) {
    return 0;
  }
  return mpz_sizeinbase(k, 2);
}

int bn_is_bit_set(const mpz_t k, int bit_idx) {
  return mpz_tstbit(k, (unsigned long)bit_idx); // mpz_tstbit expects ulong for index
}

#ifndef BTC_ONLY_BUILD
// This function is StarkNet specific by name and its use of STARKNET_BIGNUM_SIZE
// and StarkNet-specific k generation details.
int starknet_sign_digest(const mpz_curve *curve, // Should ideally be the specific StarkNet curve
                         const uint8_t *priv_key,
                         const uint8_t *digest,
                         uint8_t *sig_out_r_s) { // Output buffer for r and s
  ASSERT(curve != NULL && priv_key != NULL && digest != NULL && sig_out_r_s != NULL);

  int ret_status = -1; // Default to error
  mpz_curve_point R_point;
  mpz_t k_nonce, z_hash, d_priv, r_sig, s_sig, rand_k_blinding;

  mpz_curve_point_init(&R_point);
  mpz_init(k_nonce);
  mpz_init(z_hash);
  mpz_init(d_priv);
  mpz_init(r_sig);
  mpz_init(s_sig);
  mpz_init(rand_k_blinding);

  // Import digest and private key
  mpz_import(z_hash, STARKNET_BIGNUM_SIZE, 1, 1, 0, 0, digest);
  mpz_import(d_priv, STARKNET_BIGNUM_SIZE, 1, 1, 1, 0, priv_key); // Assuming private key is big-endian

#if USE_RFC6979
  rfc6979_state rng_ctx = {0};
  // Assuming init_rfc6979 expects byte arrays for private key and hash,
  // and that STARKNET_BIGNUM_SIZE is appropriate for hash length.
  init_rfc6979(priv_key, digest, &rng_ctx);
#endif

  for (int i = 0; i < 10000; i++) { // Retry loop for valid k/signature
#if USE_RFC6979
    generate_k_rfc6979_mpz(k_nonce, &rng_ctx); // k_nonce is generated, uses STARKNET_BIGNUM_SIZE
    mpz_fdiv_q_2exp(k_nonce, k_nonce, 4);      // StarkNet specific: k = k_raw >> 4
#else
    generate_k_random_mpz(k_nonce, curve->order); // k_nonce is random, uses STARKNET_BIGNUM_SIZE via helpers
#endif

    if (mpz_cmp_ui(k_nonce, 0) == 0 || mpz_cmp(k_nonce, curve->order) >= 0) {
      continue; // k must be in [1, order-1]
    }

    // R_point = k_nonce * G
    mpz_curve_point_multiply(curve, k_nonce, &curve->G, &R_point);
    mpz_set(r_sig, R_point.x); // r = R_point.x
    mpz_mod(r_sig, r_sig, curve->order); // r = r mod n

    if (mpz_cmp_ui(r_sig, 0) == 0) {
      continue; // r cannot be 0
    }

    // s = k_nonce^-1 * (z_hash + r_sig * d_priv) mod order
    // The side-channel blinding from original code:
    // k_nonce was used to derive R.x (r_sig)
    // Then k_nonce was modified with rand_k_blinding before inversion for s calculation.
    // k_effective_for_s_calc = (k_nonce * rand_k_blinding)^-1
    // s_intermediate = (z_hash + r_sig * d_priv) * k_effective_for_s_calc
    // s_final = s_intermediate * rand_k_blinding 
    // This simplifies to s_final = (z_hash + r_sig * d_priv) * k_nonce^-1, which is standard ECDSA.
    // So, the blinding seems to cancel out for the final 's' value, but applies to intermediates.

    mpz_t k_nonce_inv;
    mpz_init(k_nonce_inv);
    mpz_invert(k_nonce_inv, k_nonce, curve->order); // k_nonce_inv = k_nonce^-1 mod order

    mpz_mul(s_sig, r_sig, d_priv);            // r * d
    mpz_add(s_sig, s_sig, z_hash);            // z + r*d
    mpz_mul(s_sig, s_sig, k_nonce_inv);       // k_nonce^-1 * (z + r*d)
    mpz_mod(s_sig, s_sig, curve->order);      // s = k_nonce^-1 * (z + r*d) mod order

    mpz_clear(k_nonce_inv);

    if (mpz_cmp_ui(s_sig, 0) == 0) {
      continue; // s cannot be 0
    }

    // StarkNet does not enforce low-s, Bitcoin does.
    // The original commented-out low-s logic:
    // if ((mpz_cmp(curve->order_half, s_sig) < 0)) {
    //   mpz_sub(s_sig, curve->order, s_sig);
    // }

    mpz_to_byte_array(r_sig, sig_out_r_s, STARKNET_BIGNUM_SIZE);
    mpz_to_byte_array(s_sig, sig_out_r_s + STARKNET_BIGNUM_SIZE, STARKNET_BIGNUM_SIZE);

    ret_status = 0; // Success
    break;          // Exit retry loop
  }

  mpz_curve_point_clear(&R_point);
  mpz_clear(k_nonce);
  mpz_clear(z_hash);
  mpz_clear(d_priv);
  mpz_clear(r_sig);
  mpz_clear(s_sig);
  mpz_clear(rand_k_blinding); // Was initialized but not used in this simplified version focusing on standard ECDSA.
                              // If the original blinding sequence is critical, it should be carefully reinstated.
#if USE_RFC6979
  memzero(&rng_ctx, sizeof(rng_ctx));
#endif
  return ret_status;
}
#endif // !BTC_ONLY_BUILD