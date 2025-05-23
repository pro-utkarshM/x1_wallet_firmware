/**
 * @file    solana_contracts.c
 * @author  Cypherock X1 Team
 * @brief   TRON whitelisted contracts list
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

#include <solana_contracts.h>

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

const solana_token_program_t
    solana_token_program[SOLANA_WHITELISTED_TOKEN_PROGRAM_COUNT] = {
        {{0xce, 0x01, 0x0e, 0x60, 0xaf, 0xed, 0xb2, 0x27, 0x17, 0xbd, 0x63,
          0x19, 0x2f, 0x54, 0x14, 0x5a, 0x3f, 0x96, 0x5a, 0x33, 0xbb, 0x82,
          0xd2, 0xc7, 0x02, 0x9e, 0xb2, 0xce, 0x1e, 0x20, 0x82, 0x64},
         "USDT",
         6},
        {{0xc6, 0xfa, 0x7a, 0xf3, 0xbe, 0xdb, 0xad, 0x3a, 0x3d, 0x65, 0xf3,
          0x6a, 0xab, 0xc9, 0x74, 0x31, 0xb1, 0xbb, 0xe4, 0xc2, 0xd2, 0xf6,
          0xe0, 0xe4, 0x7c, 0xa6, 0x02, 0x03, 0x45, 0x2f, 0x5d, 0x61},
         "USDC",
         6},
        {{0xb5, 0xd2, 0x5a, 0xf8, 0x1f, 0xdd, 0x47, 0xe2, 0x3f, 0xc5, 0x1c,
          0xb9, 0x29, 0xf2, 0xbf, 0xf3, 0xe1, 0xbf, 0x6a, 0xd6, 0x4d, 0xf7,
          0x7d, 0x3e, 0x52, 0x3a, 0x22, 0x80, 0x23, 0xe7, 0x3e, 0x6c},
         "USDE",
         9},
        {{0x07, 0x07, 0x31, 0x2d, 0x1d, 0x41, 0xda, 0x71, 0xf0, 0xfb, 0x28,
          0x0c, 0x16, 0x62, 0xcd, 0x65, 0xeb, 0xeb, 0x2e, 0x08, 0x59, 0xc0,
          0xcb, 0xae, 0x3f, 0xdb, 0xdc, 0xb2, 0x6c, 0x86, 0xe0, 0xaf},
         "USDS",
         6},
        {{0x0c, 0xc1, 0x0f, 0x51, 0x6a, 0xaa, 0xe9, 0xc1, 0x4b, 0xa9, 0x47,
          0x1f, 0x60, 0xab, 0xd3, 0x92, 0xdc, 0xd7, 0x86, 0xd5, 0x73, 0x54,
          0xab, 0xed, 0xee, 0xe7, 0x28, 0x9d, 0xd4, 0x0a, 0x0a, 0x0a},
         "RENDER",
         8},
        {{0xbc, 0x07, 0xc5, 0x6e, 0x60, 0xad, 0x3d, 0x3f, 0x17, 0x73, 0x82,
          0xea, 0xc6, 0x54, 0x8f, 0xba, 0x1f, 0xd3, 0x2c, 0xfd, 0x90, 0xca,
          0x02, 0xb3, 0xe7, 0xcf, 0xa1, 0x85, 0xfd, 0xce, 0x73, 0x98},
         "BONK",
         5},
        {{0x1d, 0x8c, 0xcf, 0x87, 0xac, 0x01, 0x47, 0xba, 0xe7, 0x56, 0xeb,
          0x96, 0x3a, 0x2e, 0xf6, 0x24, 0x4c, 0x96, 0x91, 0x56, 0x9a, 0x8e,
          0xc0, 0x8f, 0x00, 0x20, 0xa2, 0xeb, 0x8f, 0xbd, 0xb5, 0xa1},
         "PENGU",
         6},
        {{0xf7, 0x4b, 0xe1, 0xd7, 0x6a, 0xb9, 0xa6, 0xc2, 0xbe, 0x49, 0x99,
          0x66, 0x3f, 0xc6, 0xa0, 0xe1, 0x99, 0x74, 0x00, 0x0e, 0x83, 0x6e,
          0xf3, 0x0c, 0x5b, 0x62, 0x86, 0xf4, 0x2c, 0x02, 0x0f, 0x87},
         "AI16Z",
         9},
        {{0xc5, 0xf9, 0xfb, 0x32, 0xf4, 0x91, 0x11, 0xab, 0x20, 0xc3, 0x3f,
          0x25, 0x98, 0xfc, 0x83, 0x6c, 0x11, 0x3e, 0x29, 0x18, 0x81, 0xac,
          0x21, 0xee, 0x29, 0x16, 0x93, 0x94, 0x01, 0x12, 0x44, 0xe4},
         "WIF",
         6},
        {{0x09, 0x1e, 0x73, 0xd1, 0x7a, 0x55, 0x26, 0xd4, 0x48, 0xe5, 0x89,
          0xae, 0xa5, 0xaf, 0xe7, 0xc2, 0x2c, 0xd6, 0x1c, 0x5b, 0x66, 0xa8,
          0x6a, 0x42, 0x7a, 0xb2, 0x62, 0x30, 0x95, 0x14, 0xe5, 0x5c},
         "CBBTC",
         8},
        {{0x37, 0x99, 0x8c, 0xcb, 0xf2, 0xd0, 0x45, 0x8b, 0x61, 0x5c, 0xbc,
          0xc6, 0xb1, 0xa3, 0x67, 0xc4, 0x74, 0x9e, 0x9f, 0xef, 0x73, 0x06,
          0x62, 0x2e, 0x1b, 0x1b, 0x58, 0x91, 0x01, 0x20, 0xbc, 0x9a},
         "RAY",
         6},
        {{0x02, 0xa8, 0x8b, 0x06, 0xfa, 0xb4, 0x0a, 0x8c, 0xd2, 0x93, 0xf0,
          0xc5, 0x27, 0x58, 0x7e, 0x62, 0xd2, 0xff, 0xab, 0x76, 0x6f, 0xca,
          0x08, 0xb7, 0xf6, 0xf3, 0xc9, 0x19, 0xee, 0x73, 0x1b, 0x12},
         "BNSOL",
         9},
        {{0xf5, 0xed, 0xec, 0x84, 0x71, 0xc7, 0x56, 0x24, 0xeb, 0xc4, 0x07,
          0x9a, 0x63, 0x43, 0x26, 0xd9, 0x6a, 0x68, 0x9e, 0x61, 0x57, 0xd7,
          0x9a, 0xbe, 0x8f, 0x5a, 0x6f, 0x94, 0x47, 0x28, 0x53, 0xbc},
         "PYTH",
         6},
        {{0x79, 0x78, 0xb7, 0x14, 0x45, 0x3c, 0xd3, 0xe8, 0x7a, 0xeb, 0x1f,
          0xc0, 0x9b, 0xf0, 0x67, 0xf9, 0x6c, 0xd2, 0xd4, 0xd6, 0x9b, 0x57,
          0x13, 0x95, 0xaa, 0x9b, 0xf1, 0x86, 0xaf, 0xf9, 0xda, 0x3f},
         "FARTCOIN",
         6},
        {{0x04, 0x79, 0xd9, 0xc7, 0xcc, 0x10, 0x35, 0xde, 0x72, 0x11, 0xf9,
          0x9e, 0xb4, 0x8c, 0x09, 0xd7, 0x0b, 0x2b, 0xdf, 0x5b, 0xdf, 0x9e,
          0x2e, 0x56, 0xb8, 0xa1, 0xfb, 0xb5, 0xa2, 0xea, 0x33, 0x27},
         "JUP",
         6},
        {{0xfd, 0x31, 0xf4, 0x30, 0x0c, 0xa5, 0xb0, 0x0a, 0x3e, 0x82, 0x47,
          0xb6, 0xaa, 0xd5, 0x4d, 0x9f, 0x7b, 0xd6, 0x1b, 0x26, 0x7f, 0x60,
          0x89, 0x98, 0xcc, 0x5f, 0xe9, 0xf2, 0xd9, 0x7c, 0x3d, 0x45},
         "SPX",
         8},
        {{0x0a, 0x73, 0x20, 0x93, 0x91, 0x85, 0x61, 0xf7, 0xdd, 0x7f, 0xcb,
          0xec, 0x4a, 0xbd, 0x85, 0x13, 0xde, 0xca, 0x1a, 0x96, 0x7f, 0x7a,
          0xd7, 0xa3, 0x9d, 0x63, 0xb4, 0x1e, 0xd8, 0x93, 0x80, 0x8b},
         "HNT",
         8},
        {{0x0b, 0x62, 0xba, 0x07, 0x4f, 0x72, 0x2c, 0x9d, 0x41, 0x14, 0xf2,
          0xd8, 0xf7, 0x0a, 0x00, 0xc6, 0x60, 0x02, 0x33, 0x7b, 0x9b, 0xf9,
          0x0c, 0x87, 0x36, 0x57, 0xa6, 0xd2, 0x01, 0xdb, 0x4c, 0x80},
         "MSOL",
         9},
        {{0x69, 0x27, 0xfd, 0xc0, 0x1e, 0xa9, 0x06, 0xf9, 0x6d, 0x71, 0x37,
          0x87, 0x4c, 0xdd, 0x7a, 0xda, 0xd0, 0x0c, 0xa3, 0x57, 0x64, 0x61,
          0x93, 0x10, 0xe5, 0x41, 0x96, 0xc7, 0x81, 0xd8, 0x4d, 0x5b},
         "W",
         6},
        {{0x0a, 0xfc, 0xf8, 0x96, 0x8b, 0x8d, 0xab, 0x88, 0x48, 0x1e, 0x2d,
          0x2a, 0xe6, 0x89, 0xc9, 0x52, 0xc7, 0x57, 0xae, 0xba, 0x64, 0x3e,
          0x39, 0x19, 0xe8, 0x9f, 0x2e, 0x55, 0x79, 0x5c, 0x76, 0xc1},
         "JTO",
         9},
        {{0x5d, 0x0b, 0x15, 0x9a, 0xff, 0xcb, 0xcc, 0xf1, 0x65, 0xc0, 0x9b,
          0xc2, 0xf5, 0xd4, 0xba, 0xfb, 0x4a, 0xa6, 0x34, 0x5a, 0xf7, 0x93,
          0xb9, 0xb3, 0x22, 0x2d, 0xaa, 0x40, 0x29, 0x3a, 0x95, 0x0d},
         "POPCAT",
         9},
        {{0x4a, 0xe3, 0xd3, 0x20, 0x82, 0x05, 0x44, 0xff, 0xfa, 0x2e, 0x6d,
          0xae, 0x60, 0xf8, 0xed, 0x2b, 0xc3, 0x42, 0x6d, 0x8d, 0xe3, 0xd7,
          0xf7, 0x7d, 0xdf, 0x35, 0x0c, 0x18, 0xfd, 0x6b, 0x31, 0x94},
         "GIGA",
         5},
        {{0x0a, 0xfe, 0x1d, 0x91, 0x67, 0x14, 0x22, 0xc7, 0x65, 0xc7, 0xa0,
          0x6a, 0x11, 0x39, 0xff, 0x61, 0x39, 0xd3, 0x80, 0xfc, 0xb4, 0x22,
          0xba, 0x78, 0xf7, 0x78, 0xbe, 0xd5, 0x3c, 0x69, 0x7d, 0x81},
         "JUPSOL",
         9},
        {{0xeb, 0x93, 0x11, 0x7f, 0x10, 0xdd, 0x2e, 0x3f, 0xf9, 0x6c, 0x12,
          0xc1, 0x12, 0x67, 0xf8, 0x65, 0x4e, 0xb1, 0x05, 0x0d, 0x05, 0xa5,
          0x5e, 0xaa, 0x08, 0xab, 0x80, 0xa7, 0x7c, 0x40, 0x9d, 0x1e},
         "GRASS",
         9},
        {{0x1b, 0x36, 0x97, 0x4c, 0xca, 0xbe, 0x2b, 0xdb, 0x37, 0xc7, 0xad,
          0xa3, 0xc3, 0x33, 0x45, 0x12, 0x6f, 0x97, 0x3d, 0xa0, 0xb5, 0x43,
          0x00, 0xc1, 0xae, 0x06, 0xb8, 0x80, 0xc2, 0x4a, 0xac, 0xff},
         "PNUT",
         6},
        {{0x0d, 0x5c, 0x23, 0xce, 0x2e, 0x07, 0xbb, 0x83, 0x7d, 0xb3, 0xf8,
          0xa1, 0x7a, 0x19, 0x00, 0x62, 0x49, 0xad, 0x8d, 0x11, 0xb9, 0xb5,
          0x16, 0x63, 0xf5, 0xf2, 0x0c, 0x32, 0x5c, 0xfa, 0x75, 0x63},
         "ORDI",
         9},
        {{0x05, 0x2e, 0xe1, 0x83, 0x38, 0x96, 0x96, 0x9f, 0x8c, 0xd1, 0xcd,
          0x46, 0x83, 0x18, 0xc5, 0x98, 0xc7, 0xe0, 0x58, 0x96, 0x07, 0x4a,
          0x59, 0x1c, 0x2a, 0xe0, 0x98, 0x60, 0x2f, 0x16, 0x80, 0x00},
         "MEW",
         5},
        {{0x62, 0x7d, 0xeb, 0x80, 0xf8, 0xba, 0x2a, 0xc3, 0x95, 0x45, 0x4c,
          0xc6, 0x50, 0xb4, 0xbe, 0x50, 0xd9, 0xdf, 0x61, 0x0a, 0xf3, 0x91,
          0x5b, 0xee, 0x42, 0xbe, 0x79, 0x3d, 0x93, 0xa1, 0xef, 0x9b},
         "BABYDOGE",
         1},
        {{0xb2, 0x20, 0xa6, 0x99, 0x04, 0xb6, 0xee, 0xd8, 0x8a, 0x0b, 0xe9,
          0x89, 0x14, 0x29, 0x80, 0xfc, 0xd1, 0xa8, 0x1e, 0x85, 0x47, 0x33,
          0x32, 0x83, 0x26, 0x31, 0xcb, 0xb6, 0x2e, 0x11, 0x62, 0x8f},
         "GOAT",
         6},
        {{0x76, 0x1d, 0xd6, 0x86, 0x55, 0x8c, 0xa0, 0x1d, 0xf7, 0x5a, 0x12,
          0x0d, 0x2a, 0x50, 0xdd, 0x8f, 0xf7, 0xb2, 0xde, 0xe5, 0x0d, 0xf5,
          0xf2, 0x0d, 0xec, 0x8d, 0x49, 0x23, 0x19, 0xb5, 0xdf, 0x83},
         "ZEREBRO",
         6},
        {{0x53, 0x97, 0xed, 0x2f, 0x2a, 0x5d, 0x3f, 0x90, 0x26, 0xb5, 0x63,
          0x60, 0x02, 0x91, 0x9b, 0x46, 0x61, 0x96, 0x80, 0x24, 0x7b, 0xc7,
          0x2f, 0x07, 0xc5, 0xaf, 0x48, 0x91, 0x0d, 0x42, 0x7d, 0xb1},
         "CHEX",
         8},
        {{0x00, 0x04, 0x82, 0xbe, 0xb7, 0xa2, 0xd9, 0x90, 0x95, 0x2e, 0x43,
          0xfa, 0x1b, 0xf6, 0x4f, 0xd3, 0x34, 0x6e, 0x72, 0xe1, 0xf1, 0x63,
          0xff, 0x39, 0xf2, 0x21, 0x94, 0xbc, 0x50, 0xdb, 0x17, 0xc2},
         "AIXBT",
         8},
        {{0x17, 0x92, 0x48, 0x3b, 0x6c, 0x8a, 0x2a, 0x87, 0xb7, 0x47, 0x1d,
          0x81, 0x4f, 0x95, 0x91, 0xf9, 0x39, 0x5c, 0x84, 0x0a, 0x9c, 0xe3,
          0xd9, 0xf4, 0xd5, 0xba, 0x7d, 0x3a, 0x4b, 0x8a, 0x74, 0x9e},
         "PYUSD",
         6},
        {{0x0d, 0x83, 0x23, 0xc0, 0x76, 0xf0, 0xe2, 0x87, 0x18, 0xca, 0x60,
          0xd7, 0x7e, 0x6b, 0x39, 0xce, 0xe8, 0xf2, 0x3f, 0x43, 0xcf, 0xc4,
          0xff, 0x1f, 0x58, 0x52, 0xb8, 0xfc, 0x1b, 0x94, 0xa2, 0x93},
         "BOME",
         6},
        {{0x9c, 0xdd, 0x9b, 0x46, 0x6a, 0xf3, 0x24, 0xc5, 0x8b, 0x65, 0x3f,
          0x6e, 0xac, 0x5e, 0x78, 0xf7, 0x48, 0xe5, 0x57, 0x78, 0xca, 0xed,
          0x00, 0xa9, 0x0d, 0x61, 0xe7, 0x0c, 0x06, 0x15, 0x87, 0xf8},
         "IO",
         8},
        {{0xc0, 0xee, 0xd3, 0xea, 0x17, 0xc3, 0xb0, 0x0d, 0xcf, 0xbb, 0xbe,
          0x8e, 0xe1, 0x64, 0xfe, 0x76, 0xbe, 0x81, 0x30, 0x3a, 0xf0, 0x93,
          0x42, 0xff, 0x1f, 0xd0, 0xd7, 0x05, 0x9a, 0x36, 0x45, 0xdc},
         "WOO",
         9},
        {{0x4d, 0x75, 0xa4, 0xbf, 0xf3, 0x35, 0x44, 0x72, 0x67, 0x1a, 0x94,
          0xf5, 0x78, 0x50, 0x4a, 0xbf, 0x20, 0x8f, 0xf7, 0xd1, 0xb4, 0x38,
          0xe9, 0xe8, 0x6b, 0x4a, 0x66, 0x0f, 0x5a, 0x42, 0xd5, 0x9d},
         "TBTC",
         8},
        {{0x85, 0xcd, 0xeb, 0xc2, 0x05, 0xdd, 0xdf, 0x95, 0xb8, 0x82, 0x00,
          0xab, 0xa0, 0xac, 0x9b, 0xcb, 0xb7, 0x80, 0x96, 0x32, 0x4e, 0x27,
          0x6f, 0xce, 0x85, 0xd6, 0x3c, 0x69, 0x21, 0x1f, 0x08, 0x45},
         "USDY",
         6},
        {{0x05, 0x2e, 0x98, 0x6a, 0x95, 0x5e, 0x14, 0x29, 0x68, 0xf2, 0x26,
          0xb6, 0xa1, 0x73, 0x45, 0xce, 0xa6, 0x0b, 0xfa, 0x3c, 0x8c, 0xd4,
          0x26, 0x0a, 0xfe, 0xdb, 0xcb, 0x2f, 0xba, 0x37, 0x14, 0x28},
         "ME",
         6},
        {{0x04, 0xab, 0x91, 0xa7, 0xa9, 0x18, 0xf5, 0x78, 0xd8, 0x5e, 0x51,
          0xd0, 0x1b, 0xc9, 0xe4, 0xc2, 0x80, 0x15, 0x3e, 0x5f, 0x5c, 0x77,
          0xed, 0xf8, 0xe4, 0xb5, 0xeb, 0xb3, 0xd1, 0x0c, 0x10, 0xa4},
         "GRIFFAIN",
         6},
        {{0x63, 0xab, 0xd0, 0x96, 0x70, 0x76, 0xf5, 0x8b, 0xa2, 0xed, 0xad,
          0xb4, 0x1f, 0x10, 0x71, 0x9d, 0xf1, 0x35, 0x4a, 0xbe, 0x11, 0x8f,
          0x29, 0xa8, 0xf3, 0x0e, 0xe6, 0x63, 0x94, 0x74, 0xb9, 0x47},
         "GMT",
         9},
        {{0xc6, 0xf5, 0x13, 0x34, 0x4c, 0x63, 0x0c, 0x06, 0x0e, 0x48, 0x78,
          0xe8, 0x96, 0x98, 0xa9, 0x75, 0x73, 0x41, 0xe6, 0x8e, 0x0f, 0x18,
          0xf0, 0xb3, 0x0a, 0x3d, 0xbc, 0x59, 0x59, 0x2a, 0xd3, 0x77},
         "BAT",
         8},
        {{0xbf, 0x08, 0x5a, 0x1b, 0xb5, 0x37, 0x67, 0x52, 0x00, 0xb8, 0x56,
          0xba, 0xa5, 0x6a, 0x97, 0xf0, 0x2a, 0x4f, 0x48, 0x48, 0x4f, 0x1d,
          0x57, 0x69, 0xf6, 0xdf, 0x44, 0xa0, 0xb1, 0xbf, 0xd6, 0x84},
         "DRIFT",
         6},
        {{0x27, 0x0a, 0xd0, 0x02, 0x8e, 0x97, 0x0d, 0xf7, 0x57, 0xd5, 0xf1,
          0x4f, 0x8c, 0xbb, 0x6a, 0x68, 0x10, 0xe4, 0x81, 0x39, 0x12, 0x56,
          0x08, 0xea, 0x95, 0x8b, 0x71, 0x8e, 0xb2, 0x94, 0x49, 0x20},
         "BORG",
         9},
        {{0xad, 0xd0, 0x93, 0xff, 0xa5, 0x4b, 0x9f, 0x21, 0xd5, 0xd6, 0x61,
          0xc9, 0x7c, 0x0f, 0xa0, 0x29, 0x1a, 0xc4, 0x30, 0x38, 0x4e, 0xae,
          0x77, 0x52, 0xcc, 0xf3, 0x37, 0x6b, 0x68, 0x71, 0xec, 0x88},
         "SUSHI",
         8},
        {{0x4a, 0x6a, 0x3f, 0xa9, 0x01, 0x17, 0x16, 0xb8, 0x1e, 0xbe, 0x2e,
          0x6f, 0xb5, 0xa8, 0x14, 0x72, 0xd5, 0xe3, 0x81, 0x08, 0x6d, 0x7e,
          0xf4, 0x75, 0x4e, 0xb4, 0x11, 0x11, 0x55, 0xdb, 0x4e, 0xef},
         "ARC",
         6},
        {{0x4f, 0x4a, 0x87, 0xfa, 0xdc, 0x7f, 0xf3, 0x77, 0x32, 0x91, 0xf9,
          0x9b, 0xcb, 0x3c, 0x8b, 0x6a, 0xf1, 0x58, 0x9f, 0x7a, 0x53, 0xd4,
          0x5d, 0xf1, 0xab, 0xa5, 0x2c, 0xab, 0x29, 0x6a, 0x83, 0x81},
         "FXS",
         8},
        {{0x0b, 0xbc, 0x22, 0x37, 0xbe, 0x47, 0x53, 0x50, 0xaf, 0xd9, 0x8b,
          0xec, 0x57, 0x96, 0x8d, 0xa2, 0xd8, 0xae, 0x7f, 0x47, 0x73, 0xf9,
          0x7f, 0x67, 0x4c, 0x94, 0xa7, 0x2e, 0x02, 0xa5, 0xf5, 0xea},
         "NOS",
         6},
        {{0xe3, 0x44, 0xa5, 0x2e, 0x00, 0x19, 0x39, 0x9b, 0xef, 0x02, 0xf7,
          0x62, 0xe1, 0xed, 0x8c, 0xc0, 0x5f, 0x8c, 0xfd, 0xa7, 0xbd, 0xa5,
          0x57, 0x96, 0xb9, 0xb9, 0x84, 0x1a, 0xaf, 0xe0, 0x06, 0x3f},
         "ACT",
         6},
        {{0x87, 0x90, 0xbe, 0x57, 0x84, 0x2c, 0x24, 0x8c, 0x85, 0x74, 0xd9,
          0x7a, 0x70, 0x39, 0x77, 0x88, 0x32, 0x41, 0x7e, 0xdc, 0xaf, 0xc4,
          0x6e, 0x6d, 0x2b, 0x04, 0x00, 0x83, 0xfd, 0x2e, 0x87, 0x0f},
         "FWOG",
         6},
        {{0x5a, 0x07, 0x56, 0x01, 0x65, 0x14, 0xa1, 0x2c, 0xcb, 0xeb, 0xe5,
          0x41, 0x31, 0x97, 0x7d, 0xf8, 0x8d, 0x24, 0x8d, 0xca, 0x67, 0x28,
          0x34, 0x1f, 0x06, 0x3d, 0x60, 0xb9, 0xd0, 0x36, 0x8a, 0xdf},
         "SWARMS",
         6},
        {{0x0c, 0xec, 0x34, 0x6f, 0xbc, 0x79, 0x23, 0xc8, 0xcb, 0xe3, 0xc9,
          0xfb, 0x4c, 0xfb, 0xe1, 0x2d, 0x84, 0x9a, 0x53, 0x44, 0xc6, 0x72,
          0x10, 0x1d, 0x3f, 0x82, 0xa3, 0xc3, 0x61, 0xcc, 0xef, 0x62},
         "SSOL",
         9},
        {{0xc4, 0x40, 0x51, 0xa9, 0x11, 0xb5, 0x4c, 0x7e, 0xcf, 0xfc, 0x7e,
          0xe0, 0xb0, 0xa4, 0x0a, 0xf4, 0x8b, 0x32, 0x8a, 0xe7, 0x55, 0xa9,
          0x95, 0x33, 0xc8, 0x40, 0x2c, 0xb2, 0x6d, 0xf4, 0x38, 0x07},
         "MOODENG",
         6},
        {{0x3a, 0x3e, 0x72, 0xb6, 0x7e, 0xa9, 0x4e, 0x17, 0x65, 0x00, 0x4e,
          0xf6, 0x82, 0x44, 0xf6, 0xb0, 0xb3, 0x2d, 0xdd, 0xe7, 0x43, 0xa3,
          0x3b, 0x20, 0xf9, 0x14, 0x30, 0xe1, 0xe8, 0x17, 0xc1, 0xac},
         "HONEY",
         9},
        {{0xc8, 0xeb, 0xa0, 0xc4, 0xf4, 0x01, 0x7e, 0x4d, 0x78, 0x46, 0xea,
          0x56, 0x95, 0xb0, 0xc8, 0x26, 0x27, 0xe5, 0xc1, 0x3a, 0x66, 0xfe,
          0x7f, 0x39, 0xfd, 0x84, 0x5f, 0xdd, 0x50, 0x5b, 0xc3, 0x59},
         "PEPECOIN",
         8},
};

/*****************************************************************************
 * STATIC FUNCTIONS
 *****************************************************************************/

/*****************************************************************************
 * GLOBAL FUNCTIONS
 *****************************************************************************/
