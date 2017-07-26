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
 * \file fcore.c
 * \brief netflow fiter tree (abstract syntax tree) evaluation function and structures
 */

#include "fcore.h"
#include "ffilter.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>


ff_attr_t ff_validate(ff_type_t type, ff_oper_t op, tcore* data, ff_lvalue_t* info)
{
	tcore* fl = data;

	if (op == FF_OP_EQ)
		switch(type) {
		case FF_TYPE_INT64: return FFAT_EQ_I8;
		case FF_TYPE_INT32: return FFAT_EQ_I4;
		case FF_TYPE_INT16: return FFAT_EQ_I2;
		case FF_TYPE_INT8: return FFAT_EQ_I1;
		case FF_TYPE_SIGNED: return FFAT_EQ_I;
		case FF_TYPE_SIGNED_BIG: return FFAT_EQ_IBE;

		case FF_TYPE_UINT64: return FFAT_EQ_UI8;
		case FF_TYPE_UINT32: return FFAT_EQ_UI4;
		case FF_TYPE_UINT16: return FFAT_EQ_UI2;
		case FF_TYPE_UINT8: return FFAT_EQ_UI1;

		case FF_TYPE_TIMESTAMP:
		case FF_TYPE_UNSIGNED: return FFAT_EQ_UI;

		case FF_TYPE_TIMESTAMP_BIG:
		case FF_TYPE_UNSIGNED_BIG: return FFAT_EQ_UIBE;

		case FF_TYPE_DOUBLE: return FFAT_EQ_RE;
		case FF_TYPE_STRING: return FFAT_EQ_STR;
		case FF_TYPE_MAC: return FFAT_EQ_MAC;

		case FF_TYPE_ADDR:
			if (fl->net.ver == 4 && fl->net.mask.data[3] == 0) {
				return FFAT_EQ_AD4;
			} else if (fl->net.ver == 6) {
				if (fl->net.mask.data[0] == 0 &&
				    fl->net.mask.data[1] == 0 &&
					fl->net.mask.data[2] == 0 &&
					fl->net.mask.data[3] == 0)
				return FFAT_EQ_AD6;
			}
			// Prefix compare
			return FFAT_EQ_ADP;

		case FF_TYPE_MPLS:
			if (info->options & FF_OPTS_MPLS_LABEL) {
				if(info->n <11) {
					fl->mpls.label = info->n;
					return FFAT_EQ_MLX;
				}
				// return FFAT_EQ_ML; //Nuance ... any label or label on top ?
			} else if (info->options & FF_OPTS_MPLS_EXP) {
				if(info->n < 11) {
					fl->mpls.label = info->n;
					return FFAT_EQ_MEX;
				}
				return FFAT_ERR;
			} else if (info->options & FF_OPTS_MPLS_EOS) {
				return FFAT_EQ_MES;
			}
			return FFAT_EQ_ML;

		default:;
		}
	else if (op == FF_OP_GT)
		switch(type) {
		case FF_TYPE_INT64: return FFAT_GT_I8;
		case FF_TYPE_INT32: return FFAT_GT_I4;
		case FF_TYPE_INT16: return FFAT_GT_I2;
		case FF_TYPE_INT8: return FFAT_GT_I1;
		case FF_TYPE_SIGNED: return FFAT_GT_I;
		case FF_TYPE_SIGNED_BIG: return FFAT_GT_IBE;

		case FF_TYPE_UINT64: return FFAT_GT_UI8;
		case FF_TYPE_UINT32: return FFAT_GT_UI4;
		case FF_TYPE_UINT16: return FFAT_GT_UI2;
		case FF_TYPE_UINT8: return FFAT_GT_UI1;
		case FF_TYPE_TIMESTAMP:
		case FF_TYPE_UNSIGNED: return FFAT_GT_UI;

		case FF_TYPE_TIMESTAMP_BIG:
		case FF_TYPE_UNSIGNED_BIG: return FFAT_GT_UIBE;

		case FF_TYPE_DOUBLE: return FFAT_GT_RE;

		case FF_TYPE_MPLS:
			if (info->options & FF_OPTS_MPLS_LABEL) {
				if(info->n < 11) {
					fl->mpls.label = info->n;
					return FFAT_GT_MLX;
				}
				return FFAT_ERR;
				//return FFAT_GT_ML; //Nuance ... any label or label on top ?
			} else if (info->options & FF_OPTS_MPLS_EXP) {
				if(info->n < 11) {
					fl->mpls.label = info->n;
					return FFAT_GT_MEX;
				}
				return FFAT_ERR;
			} else if (info->options & FF_OPTS_MPLS_EOS) {
				return FFAT_GT_MES;
			}
			//return FFAT_GT_ML; //Forbid compare </> on any label
			return FFAT_ERR;
		default:;
		}
	else if (op == FF_OP_LT) {
		switch(type) {

		case FF_TYPE_INT64: return FFAT_LT_I8;
		case FF_TYPE_INT32: return FFAT_LT_I4;
		case FF_TYPE_INT16: return FFAT_LT_I2;
		case FF_TYPE_INT8: return FFAT_LT_I1;
		case FF_TYPE_SIGNED: return FFAT_LT_I;
		case FF_TYPE_SIGNED_BIG: return FFAT_LT_IBE;

		case FF_TYPE_UINT64: return FFAT_LT_UI8;
		case FF_TYPE_UINT32: return FFAT_LT_UI4;
		case FF_TYPE_UINT16: return FFAT_LT_UI2;
		case FF_TYPE_UINT8: return FFAT_LT_UI1;

		case FF_TYPE_TIMESTAMP:
		case FF_TYPE_UNSIGNED: return FFAT_LT_UI;

		case FF_TYPE_TIMESTAMP_BIG:
		case FF_TYPE_UNSIGNED_BIG: return FFAT_LT_UIBE;

		case FF_TYPE_DOUBLE: return FFAT_LT_RE;
		case FF_TYPE_MPLS:
			if (info->options & FF_OPTS_MPLS_LABEL) {
				if(info->n < 11) {
					fl->mpls.label = info->n;
					return FFAT_LT_MLX;
				} else if (info->n) {
					return FFAT_ERR;
					//return FFAT_LT_ML; //Nuance ... any label or label on top ?
				}
			} else if (info->options & FF_OPTS_MPLS_EXP) {
				if(info->n < 11) {
					fl->mpls.label = info->n;
					return FFAT_LT_MEX;
				}
				return FFAT_ERR;

			} else if (info->options & FF_OPTS_MPLS_EOS) {
				return FFAT_LT_MES;
			}
			//return FFAT_LT_ML; //Forbid compare </> on any label
			return FFAT_ERR;
		default:;
		}
	}
	else if (op == FF_OP_ISSET) {
		switch(type) {

		case FF_TYPE_INT64: return FFAT_IS_I8;
		case FF_TYPE_INT32: return FFAT_IS_I4;
		case FF_TYPE_INT16: return FFAT_IS_I2;
		case FF_TYPE_INT8: return FFAT_IS_I1;

		case FF_TYPE_SIGNED: return FFAT_IS_I;
		case FF_TYPE_SIGNED_BIG: return FFAT_IS_IBE;

		case FF_TYPE_UINT64: return FFAT_IS_UI8;
		case FF_TYPE_UINT32: return FFAT_IS_UI4;
		case FF_TYPE_UINT16: return FFAT_IS_UI2;
		case FF_TYPE_UINT8: return FFAT_IS_UI1;

		case FF_TYPE_UNSIGNED: return FFAT_IS_UI;
		case FF_TYPE_UNSIGNED_BIG: return FFAT_IS_UIBE;

		case FF_TYPE_STRING: return FFAT_IS_STR;

		case FF_TYPE_MPLS:
			if (info->options & FF_OPTS_MPLS_LABEL) {
				if(info->n < 11) {
					fl->mpls.label = info->n;
					return FFAT_IS_MLX;
				}
				return FFAT_ERR;
				//return FFAT_EQ_ML; //Nuance ... any label or label on top ?
			} else if (info->options & FF_OPTS_MPLS_EXP) {
				if(info->n < 11) {
					fl->mpls.label = info->n;
					return FFAT_IS_MEX;
				}
			}
			//return FFAT_IS_ML; //Forbid compare </> on any label
			return FFAT_ERR;
		default: break;
		}
	} else if (op == FF_OP_IN) {
		return FFAT_IN;
	}

	return FFAT_ERR;
}


/* Big suffix refers to what endiannes expect from data function,
   note that comparation uses native format of architecture */

/**
 *
 * \param buf contains pointer to data, if data alone are in buffer still, first in buffer is pointer
 * \param size nonzero if relevant
 * \param node node to evaluate
 * \return
 */
int ff_oper_eval_V2(char* buf, size_t size, ff_node_t *node)
{
	const tcore* const fl = node->value; //filter node data
	const trec* const rc = (trec*) *((char**)buf); //record data
	trec hord; //Host byte order converted value

	//Get this shit going fist integer then string etc...
	int res = 0;
	unsigned int x = 0;

	//Handle variable length types, big endians and so on, pre-copy data
	//Pre-process switch
	switch ((ff_attr_t)node->type) {

	case FFAT_EQ_UIBE:
	case FFAT_GT_UIBE:
	case FFAT_LT_UIBE:
	case FFAT_IS_UIBE:
	case FFAT_EQ_IBE:
	case FFAT_GT_IBE:
	case FFAT_LT_IBE:
	case FFAT_IS_IBE:

		hord.ui = 0; //Copy and transform
		if (size == 8) {
			hord.ui = ntohll(rc->ui);
		} else if (size == 4) {
			hord.ui4 = ntohl(rc->ui4);
		} else if (size == 2) {
			hord.ui2 = ntohs(rc->ui2);
		} else if (size == 1) {
			hord.ui1 = rc->ui1;
		} else {
			return -1;
		}
		break;

	case FFAT_EQ_UI:
	case FFAT_GT_UI:
	case FFAT_LT_UI:
	case FFAT_IS_UI:
	case FFAT_EQ_I:
	case FFAT_GT_I:
	case FFAT_LT_I:
	case FFAT_IS_I:

		hord.ui = 0; //Copy
		if (size == 8) {
			hord.ui = rc->ui;
		} else if (size == 4) {
			hord.ui4 = rc->ui4;
		} else if (size == 2) {
			hord.ui2 = rc->ui2;
		} else if (size == 1) {
			hord.ui1 = rc->ui1;
		} else {
			return -1;
		}
		break;


	/* Some pre preprocessing on ip data - not worth doing
	case FFAT_EQ_ADP:
	case FFAT_EQ_AD6:
	case FFAT_EQ_AD4:
		if (size == 4) { //realign to 16B
			memset(&hord.ip, 0, sizeof(ff_ip_t));
			hord.ip.data[3] = rc->ip.data[0];
			rc = &hord;
		} else if (size != sizeof(ff_ip_t)) {
			return -1;
		}
	*/

	default: ;
	}


	// Eval switch
	switch ((ff_attr_t)node->type) {

	case FFAT_EQ_UIBE:
	case FFAT_EQ_UI:
		return hord.ui == fl->ui;
	case FFAT_EQ_UI8:
		return rc->ui == fl->ui;
	case FFAT_EQ_UI4:
		return rc->ui4 == fl->ui;
	case FFAT_EQ_UI2:
		return rc->ui2 == fl->ui;
	case FFAT_EQ_UI1:
		return rc->ui1 == fl->ui;

	case FFAT_GT_UIBE:
	case FFAT_GT_UI:
		return hord.ui > fl->ui;
	case FFAT_GT_UI8:
		return rc->ui > fl->ui;
	case FFAT_GT_UI4:
		return rc->ui4 > fl->ui;
	case FFAT_GT_UI2:
		return rc->ui2 > fl->ui;
	case FFAT_GT_UI1:
		return rc->ui1 > fl->ui;

	case FFAT_LT_UIBE:
	case FFAT_LT_UI:
		return hord.ui < fl->ui;
	case FFAT_LT_UI8:
		return rc->ui < fl->ui;
	case FFAT_LT_UI4:
		return rc->ui4 < fl->ui;
	case FFAT_LT_UI2:
		return rc->ui2 < fl->ui;
	case FFAT_LT_UI1:
		return rc->ui1 < fl->ui;

	case FFAT_IS_UIBE:
	case FFAT_IS_UI:
		return (hord.ui & fl->ui) == fl->ui;
	case FFAT_IS_UI8:
		return (rc->ui & fl->ui) == fl->ui;
	case FFAT_IS_UI4:
		return (rc->ui4 & fl->ui) == fl->ui;
	case FFAT_IS_UI2:
		return (rc->ui2 & fl->ui) == fl->ui;
	case FFAT_IS_UI1:
		return (rc->ui1 & fl->ui) == fl->ui;


	case FFAT_EQ_IBE:
	case FFAT_EQ_I:
		return hord.i == fl->i;
	case FFAT_EQ_I8:
		return rc->i == fl->i;
	case FFAT_EQ_I4:
		return rc->i4 == fl->i;
	case FFAT_EQ_I2:
		return rc->i2 == fl->i;
	case FFAT_EQ_I1:
		return rc->i1 == fl->i;

	case FFAT_GT_IBE:
	case FFAT_GT_I:
		return hord.i > fl->i;
	case FFAT_GT_I8:
		return rc->i > fl->i;
	case FFAT_GT_I4:
		return rc->i4 > fl->i;
	case FFAT_GT_I2:
		return rc->i2 > fl->i;
	case FFAT_GT_I1:
		return rc->i1 > fl->i;

	case FFAT_LT_IBE:
	case FFAT_LT_I:
		return hord.i < fl->i;
	case FFAT_LT_I8:
		return rc->i < fl->i;
	case FFAT_LT_I4:
		return rc->i4 < fl->i;
	case FFAT_LT_I2:
		return rc->i2 < fl->i;
	case FFAT_LT_I1:
		return rc->i1 < fl->i;

	case FFAT_IS_IBE:
	case FFAT_IS_I:
		return (hord.i & fl->i) == fl->i;
	case FFAT_IS_I8:
		return (rc->i & fl->i) == fl->i;
	case FFAT_IS_I4:
		return (rc->i4 & fl->i) == fl->i;
	case FFAT_IS_I2:
		return (rc->i2 & fl->i) == fl->i;
	case FFAT_IS_I1:
		return (rc->i1 & fl->i) == fl->i;


	case FFAT_EQ_RE:
		return rc->real == fl->real;
	case FFAT_GT_RE:
		return rc->real > fl->real;
	case FFAT_LT_RE:
		return rc->real < fl->real;

	case FFAT_EQ_STR:
		return !strncmp(&rc->str, &fl->str, node->vsize);
	case FFAT_IS_STR:
		return strcasestr(&rc->str, &fl->str) != NULL; //Make it safe

	case FFAT_EQ_MAC:
		return !memcmp(&rc->ui, &fl->ui, sizeof(ff_mac_t));

	case FFAT_EQ_AD4:
		if (size == 4)
			return (rc->ip.data[0] == fl->net.ip.data[3]);
		return	!rc->ip.data[0] &&
				!rc->net.ip.data[1] &&
				!rc->net.ip.data[2] &&
		        (rc->ip.data[0] == fl->net.ip.data[3]);

	case FFAT_EQ_AD6:
		if (size == 4)
			return 0;
		return !memcmp(&rc->ip, fl->ip.data, sizeof(ff_ip_t)); //Exact compare

	case FFAT_EQ_ADP:    //Prefix eval
		if (size == 4) { //realign to 16B
			memset(&hord.ip, 0, sizeof(ff_ip_t));
			hord.ip.data[3] = rc->ip.data[0];

			res = 1;
			for (x = 0; x < 4; x++)
				res &= ((hord.ip.data[x] & fl->net.mask.data[x])
				        == fl->net.ip.data[x]);
			return res;
		}

		res = 1;
		for (x = 0; x < 4; x++)
			res &= ((rc->ip.data[x] & fl->net.mask.data[x])
			       == fl->net.ip.data[x]);
		return res;

	// This type is used only of no options are set and EQ operator is used
	case FFAT_EQ_ML:
		res = 0;
		for (x=0; x < 10; x++) {
			res = fl->mpls.val == rc->mpls.id[x].label;
			if (res || rc->mpls.id[x].eos) break;
		}
		return res;
	// Dead
	case FFAT_GT_ML:
		res = 0;
		for (x=0; x < 10; x++) {
			res = fl->mpls.val < rc->mpls.id[x].label;
			if (res || rc->mpls.id[x].eos) break;
		}
		return res;
	// Dead
	case FFAT_LT_ML:
		res = 0;
		for (x=0; x < 10; x++) {
			res = fl->mpls.val > rc->mpls.id[x].label;
			if (res || rc->mpls.id[x].eos) break;
		}
		return res;

    // To eval specific label
	case FFAT_EQ_MLX:
		return fl->mpls.val == rc->mpls.id[fl->mpls.label - 1].label;
	case FFAT_GT_MLX:
		return fl->mpls.val < rc->mpls.id[fl->mpls.label - 1].label;
	case FFAT_LT_MLX:
		return fl->mpls.val > rc->mpls.id[fl->mpls.label - 1].label;

    // To eval exp bit of specific label
	case FFAT_EQ_MEX:
		return fl->mpls.val == rc->mpls.id[fl->mpls.label - 1].exp;
	case FFAT_GT_MEX:
		return fl->mpls.val < rc->mpls.id[fl->mpls.label - 1].exp;
	case FFAT_LT_MEX:
		return fl->mpls.val > rc->mpls.id[fl->mpls.label - 1].exp;
	case FFAT_IS_MEX:
		return fl->mpls.val == (fl->mpls.val & rc->mpls.id[fl->mpls.label - 1].exp);

    // To eval which label is atop of stack EOS bit is set
	case FFAT_EQ_MES:
		for (x = 0; x < 10; x++)
			if (rc->mpls.id[x].eos) {
				break;
			}
		return (fl->mpls.val == x+1);

	case FFAT_GT_MES:
		for (x = 0; x < 10; x++)
			if (rc->mpls.id[x].eos) {
				break;
			}
		return (fl->mpls.val < x+1);

	case FFAT_LT_MES:
		for (x = 0; x < 10; x++)
			if (rc->mpls.id[x].eos) {
				break;
			}
		return (fl->mpls.val > x+1);

	default: return -1;
	}
}
