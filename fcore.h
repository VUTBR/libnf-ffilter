/*

 Copyright (c) 2015-2017, Imrich Stoffa

 This file is part of libnf.net project.

 Libnf is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 Libnf is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with libnf.  If not, see <http://www.gnu.org/licenses/>.

*/


/**
 * \file fcore.h
 * \brief netflow fiter tree (abstract syntax tree) evaluation function and structures
 */

#ifndef NFFILTER_FCORE_H
#define NFFILTER_FCORE_H

#include "ffilter.h"

/**
 * \brief Enumerator for validation of type, operator combinations
 * 1 Dim switch uses this to tidy up a code and utilize possible optimizations
 * EQ/GT/LT/IS are operators,
 * I/UI - integers followed by size in bytes, no size means one of 1/2/4/8 bytes,
 *        BE means big endian variant expected from wrapper
 * ADP - addres with prefix
 * AD4 - v4 address
 * AD6 - v6 address
 * RE - double
 * TS - timestamp which is equivalent to UI/UIB only string convertor differs
 * M__ - mpls operators L - label one of 10, LX - label x is requested,
 * MEX - exp bits on top of stack, MES - check which label is top of stack
 */
typedef enum ff_attr_e{
	FFAT_ERR,
	FFAT_EQ_UI,
	FFAT_EQ_UIBE,
	FFAT_EQ_UI8,
	FFAT_EQ_UI4,
	FFAT_EQ_UI2,
	FFAT_EQ_UI1,
	FFAT_EQ_I,
	FFAT_EQ_IBE,
	FFAT_EQ_I8,
	FFAT_EQ_I4,
	FFAT_EQ_I2,
	FFAT_EQ_I1,
	FFAT_EQ_RE,
	FFAT_EQ_STR,
	FFAT_EQ_TSB,
	FFAT_EQ_TS,
	FFAT_EQ_MAC,
	FFAT_EQ_AD4,
	FFAT_EQ_AD6,
	FFAT_EQ_ADP,
	FFAT_EQ_ML,
	FFAT_EQ_MLX,
	FFAT_EQ_MEX,
	FFAT_EQ_MES,

	FFAT_GT_UI,
	FFAT_GT_UIBE,
	FFAT_GT_UI8,
	FFAT_GT_UI4,
	FFAT_GT_UI2,
	FFAT_GT_UI1,
	FFAT_GT_I,
	FFAT_GT_IBE,
	FFAT_GT_I8,
	FFAT_GT_I4,
	FFAT_GT_I2,
	FFAT_GT_I1,
	FFAT_GT_RE,
	FFAT_GT_STR,
	FFAT_GT_TSB,
	FFAT_GT_TS,
	FFAT_GT_MAC,
	FFAT_GT_AD4,
	FFAT_GT_AD6,
	FFAT_GT_ADP,
	FFAT_GT_ML,
	FFAT_GT_MLX,
	FFAT_GT_MEX,
	FFAT_GT_MES,

	FFAT_LT_UI,
	FFAT_LT_UIBE,
	FFAT_LT_UI8,
	FFAT_LT_UI4,
	FFAT_LT_UI2,
	FFAT_LT_UI1,
	FFAT_LT_I,
	FFAT_LT_IBE,
	FFAT_LT_I8,
	FFAT_LT_I4,
	FFAT_LT_I2,
	FFAT_LT_I1,
	FFAT_LT_RE,
	FFAT_LT_STR,
	FFAT_LT_TSB,
	FFAT_LT_TS,
	FFAT_LT_MAC,
	FFAT_LT_AD4,
	FFAT_LT_AD6,
	FFAT_LT_ADP,
	FFAT_LT_ML,
	FFAT_LT_MLX,
	FFAT_LT_MEX,
	FFAT_LT_MES,

	FFAT_IS_UI,
	FFAT_IS_UIBE,
	FFAT_IS_UI8,
	FFAT_IS_UI4,
	FFAT_IS_UI2,
	FFAT_IS_UI1,
	FFAT_IS_I,
	FFAT_IS_IBE,
	FFAT_IS_I8,
	FFAT_IS_I4,
	FFAT_IS_I2,
	FFAT_IS_I1,
	FFAT_IS_RE,
	FFAT_IS_STR,
	FFAT_IS_TSB,
	FFAT_IS_TS,
	FFAT_IS_MAC,
	FFAT_IS_AD4,
	FFAT_IS_AD6,
	FFAT_IS_ADP,
	FFAT_IS_ML,
	FFAT_IS_MLX,
	FFAT_IS_MEX,
	FFAT_IS_MES,

    FFAT_INS_UI,
    FFAT_INS_UIBE,
    FFAT_INS_UI8,
    FFAT_INS_UI4,
    FFAT_INS_UI2,
    FFAT_INS_UI1,
    FFAT_INS_I,
    FFAT_INS_IBE,
    FFAT_INS_I8,
    FFAT_INS_I4,
    FFAT_INS_I2,
    FFAT_INS_I1,
    FFAT_INS_RE,
    FFAT_INS_STR,
    FFAT_INS_TSB,
    FFAT_INS_TS,
    FFAT_INS_MAC,
    FFAT_INS_AD4,
    FFAT_INS_AD6,
    FFAT_INS_ADP,
    FFAT_INS_ML,
    FFAT_INS_MLX,
    FFAT_INS_MEX,
    FFAT_INS_MES,

	FFAT_EXIST,
	FFAT_IN

} ff_attr_t;

ff_attr_t ff_negate(ff_attr_t o);

ff_attr_t ff_validate(ff_type_t type, ff_oper_t op, char* data, ff_lvalue_t* info);

int ff_oper_eval_V2(char* buf, size_t size, ff_node_t *node);

#endif //NFFILTER_FCORE_H
