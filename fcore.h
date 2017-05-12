//
// Created by istoffa on 5/11/17.
//

#ifndef NFFILTER_FCORE_H
#define NFFILTER_FCORE_H

#include "ffilter.h"

/**
 * \brief Enumerator for validation of type, operator combinations
 * 1 Dim switch uses this to tidy up a code and utilize possible optimizations
 * EQ/GT/LT/IS are operators,
 * I/UI - integers followed by size in bytes,
 * 	no size means one of 1/2/4/8 bytes, BE means big endian variant expected from wrapper
 * ADP - addres with prefix
 * AD4 - v4 address
 * AD6 - v6 address
 * RE - double
 * TS - timestamp which is equivalent to UI/UIB only string convertor differs
 * M__ - mpls operators L - label one of 10, LX - label x is requested,
 * 	EX - exp bits on top of stack, ES - check which label is top of stack
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

	FFAT_EXIST

} ff_attr_t;

typedef union ff_core_u {
	uint64_t ui;
	uint32_t ui4;
	uint16_t ui2;
	uint8_t ui1;
	int64_t i;
	int32_t i4;
	int16_t i2;
	int8_t i1;
	double real;
	ff_mpls_t mpls;
	char* str;
	ff_net_t* net;
	ff_ip_t* ip;
} tcore;

ff_attr_t ff_validate(ff_type_t type, ff_oper_t op, char* data, ff_lvalue_t* info);

int ff_oper_eval_V2(char* buf, size_t size, ff_node_t *node);

#endif //NFFILTER_FCORE_H
