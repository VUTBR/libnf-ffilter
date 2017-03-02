//
// Created by istoffa on 22.8.2016.
//

#include <gtest/gtest.h>
#include <arpa/inet.h>

extern "C" {
#include "profiles/ffilter.h"

}

//TODO: Test ffilter interface
int main(int argc, char** argv) {
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

enum test_record_field {
	FLD_NONE = 0,
	FLD_SRC_NUMBER64 = 1,
	FLD_DST_NUMBER64,
	FLD_NUMBER32,
	FLD_NUMBER16,
	FLD_NUMBER8_1,
	FLD_NUMBER8_2,
	FLD_NUMBER8_3,
	FLD_NUMBER8_4,
	FLD_REAL,
	FLD_MAC_ADDR,
	FLD_MPLS_STACK_LABEL,
	FLD_IP_ADDRV4,
	FLD_IP_ADDRV6,
	FLD_TIMESTAMP,
	FLD_MESSAGE,
	FLD_BINARY_HEAP,
};

union mock_rec {
	double real;
	int64_t i64;
	int32_t i32;
	int16_t i16;
	int8_t i8
	char message[40];
};

/**
 * \brief Mockup lookup func callback to test all ffilter supported data types
 * Lookup func sets lvalue of field according to first letter of valstr and
 * @param filter
 * @param valstr Name of field
 * @param lvalue
 * @return FF_OK on success
 */
ff_error_t test_lookup_func (struct ff_s *filter, const char *valstr, ff_lvalue_t *lvalue)
{
	ff_type_t type;
	ff_extern_id_t id;
	id.index = valstr[0];

	lvalue->id[0].index = FLD_NONE;
	lvalue->options = FF_OPTS_NONE;

	if (!strcmp(valstr, "uint")) { 
		type = FF_TYPE_UNSIGNED;
		lvalue->id[0].index = FLD_SRC_NUMBER64;
		lvalue->id[1].index = FLD_DST_NUMBER64;
		lvalue->options |= FF_OPTS_MULTINODE;

	} else if (!strcmp(valstr, "src uint")) { 
		type = FF_TYPE_UNSIGNED;
		lvalue->id[0].index = FLD_SRC_NUMBER64;

	} else if (!strcmp(valstr, "dst uint")) {
		type = FF_TYPE_UNSIGNED;
		lvalue->id[0].index = FLD_DST_NUMBER64;

	} else if (!strcmp(valstr, "ui64")) {
		type = FF_TYPE_UINT64;
		lvalue->id[0].index = FLD_SRC_NUMBER64;

	} else if (!strcmp(valstr, "ui32")) { type = FF_TYPE_UINT32;
		lvalue->id[0].index = FLD_NUMBER32;

	} else if (!strcmp(valstr, "ui16")) { type = FF_TYPE_UINT16;
		lvalue->id[0].index = FLD_NUMBER16;

	} else if (!strcmp(valstr, "ui8")) { type = FF_TYPE_UINT8;
		lvalue->id[0].index = FLD_NUMBER8_1;

	} else if (!strcmp(valstr, "ui8Multinode")) { type = FF_TYPE_UINT8;
		lvalue->id[0].index = FLD_NUMBER8_1;
		lvalue->id[1].index = FLD_NUMBER8_2;
		lvalue->id[2].index = FLD_NUMBER8_3;
		lvalue->id[3].index = FLD_NUMBER8_4;
		lvalue->options |= FF_OPTS_MULTINODE;

	} else if (!strcmp(valstr, "int")) { type = FF_TYPE_SIGNED;
		lvalue->id[0].index = FLD_SRC_NUMBER64;
		lvalue->id[1].index = FLD_DST_NUMBER64;
		lvalue->options |= FF_OPTS_MULTINODE;

	} else if (!strcmp(valstr, "src int")) { type = FF_TYPE_SIGNED;
		lvalue->id[0].index = FLD_SRC_NUMBER64;

	} else if (!strcmp(valstr, "dst int")) { type = FF_TYPE_SIGNED;
		lvalue->id[0].index = FLD_DST_NUMBER64;

	} else if (!strcmp(valstr, "i64")) { type = FF_TYPE_INT64;
		lvalue->id[0].index = FLD_SRC_NUMBER64;

	} else if (!strcmp(valstr, "i32")) { type = FF_TYPE_INT32;
		lvalue->id[0].index = FLD_NUMBER32;

	} else if (!strcmp(valstr, "i16")) { type = FF_TYPE_INT16;
		lvalue->id[0].index = FLD_NUMBER16;

	} else if (!strcmp(valstr, "i8")) { type = FF_TYPE_INT8;
		lvalue->id[0].index = FLD_NUMBER8_1;

	} else if (!strcmp(valstr, "real")) { type = FF_TYPE_DOUBLE;
		lvalue->id[0].index = FLD_REAL;

	} else if (!strcmp(valstr, "mac")) { type = FF_TYPE_MAC;
		lvalue->id[0].index = FLD_MAC_ADDR;

	} else if (!strcmp(valstr, "mplsLabel")) { type = FF_TYPE_MPLS;			//Unimplemented
		lvalue->id[0].index = FLD_MPLS_STACK_LABEL;

	} else if (!strcmp(valstr, "mplsExp")) { type = FF_TYPE_MPLS;			//Unimplemented
		lvalue->id[0].index = FLD_MPLS_STACK_LABEL;
		//lvalue->options |= //Set exp selector

	} else if (!strcmp(valstr, "mplsEos")) { type = FF_TYPE_MPLS;			//Unimplemented
		lvalue->id[0].index = FLD_MPLS_STACK_LABEL;
		//lvalue->options |= //Set eos selector

	} else if (!strcmp(valstr, "v4addr")) { type = FF_TYPE_ADDR;
		lvalue->id[0].index = FLD_IP_ADDRV4;

	} else if (!strcmp(valstr, "v6addr")) { type = FF_TYPE_ADDR;
		lvalue->id[0].index = FLD_IP_ADDRV6;

	} else if (!strcmp(valstr, "addr")) { type = FF_TYPE_ADDR;
		lvalue->id[0].index = FLD_IP_ADDRV4;
		lvalue->id[1].index = FLD_IP_ADDRV6;

	} else if (!strcmp(valstr, "timestamp")) { type = FF_TYPE_TIMESTAMP;
		lvalue->id[0].index = FLD_TIMESTAMP;

	} else if (!strcmp(valstr, "message")) { type = FF_TYPE_STRING;
		lvalue->id[0].index = FLD_MESSAGE;

	} else if (!strcmp(valstr, "heap")) { type = FF_TYPE_UNSUPPORTED;
		lvalue->id[0].index = FLD_BINARY_HEAP;
	} else if (!strcmp(valstr, "none")) { type = FF_TYPE_UINT8;
		lvalue->id[0].index = FLD_NONE;
	} else {
		return FF_ERR_OTHER;
	}

	lvalue->type = type;

	return FF_OK;
}

/**
 * \breif Mockup data func callback to test all ffilter supported data types
 * Test data func selects data from record based on external identification,
 * which was set by lookup callback \see test_lookup_func
 * @param filter
 * @param rec test_record reference
 * @param extid Ident. of field
 * @param buf Selected data are copied here
 * @param size Length of selected data
 * @return FF_OK on data copied
 */
ff_error_t test_data_func (struct ff_s *filter, void *rec, ff_extern_id_t extid, char* buf, size_t *size)
{
	struct test_record *trec = (struct test_record*)rec;

	const char *data;

	switch(extid.index) {
	case FLD_SRC_NUMBER64:
	case FLD_DST_NUMBER64:
		*size = 8;
	case FLD_NUMBER32:
		*size = 4;
	case FLD_NUMBER16:
		*size = 2;
	case FLD_NUMBER8_1:
	case FLD_NUMBER8_2:
	case FLD_NUMBER8_3:
	case FLD_NUMBER8_4:
		*size = 1;
	case FLD_REAL:
		*size = 8;
	case FLD_MAC_ADDR:
		*size = 6;
	case FLD_MPLS_STACK_LABEL:
		*size = 20;
	case FLD_IP_ADDRV4:
		*size = 4;
	case FLD_IP_ADDRV6:
		*size = 16;
	case FLD_TIMESTAMP:
	
	case FLD_MESSAGE:
	case FLD_BINARY_HEAP: 
	case FLD_NONE:

	default : *size = 0; return FF_ERR_OTHER;
	}

	memcpy(buf, data, *size);
	return FF_OK;
}

/**
 * \brief Mockup map callback func to test constants translation
 * Test constants translatoin function converts literals for signed and unsigned field type
 * For testing purposes only two constants are available for now
 * tenBelow -> -10
 * megabyte -> 1024*1024
 *
 * @param filter
 * @param valstr Literal
 * @param test_type Data type of field
 * @param extid	Field identification
 * @param buf Translated data are copied here
 * @param size Length of data copied
 * @return FF_OK on successfull translation
 */
ff_error_t test_rval_map_func (struct ff_s * filter, const char *valstr, ff_type_t test_type, ff_extern_id_t extid, char* buf, size_t *size)
{
	if (test_type == FF_TYPE_SIGNED || test_type == FF_TYPE_UNSIGNED || test_type == FF_TYPE_INT16) {
		if (!strcmp(valstr, "tenBelow")) {
			*(uint64_t *) buf = -10;
			*size = sizeof(uint64_t);
		} else if (!strcmp(valstr, "kilobyte")) {
			*(uint64_t *) buf = 1000;
			*size = sizeof(uint64_t);
		} else {
			*size = 0;
			return FF_ERR_OTHER;
		}
		return FF_OK;
	}
	return FF_ERR_OTHER;
}


class filter_types_test : public :: testing::Test {
protected:

	char *expr;
	union mock_rec rec;
	ff_options_t* test_callbacks;
	ff_t *filter;
	char *buffer;

	virtual void SetUp() {
		ff_options_init(&test_callbacks); //Prepare structure for callbacks
		buffer = (char*)malloc(FF_MAX_STRING);	//Alloc extra buffer

		test_callbacks->ff_data_func = test_data_func;
		test_callbacks->ff_lookup_func = test_lookup_func;
		test_callbacks->ff_rval_map_func = test_rval_map_func;

		memset(&rec, 0,sizeof(struct test_record));
		filter = NULL;
		expr = NULL;
	}

	virtual void TearDown() {
		ff_options_free(test_callbacks);
		free(buffer);
		//ff_free(filter);
	}

	void fillInt(int64_t val) {
		rec.i64 = val;
	}
	void fillInt(int32_t val) {
		rec.i32 = val;
	}
	void fillInt(int16_t val) {
		rec.i16 = val;
	}
	void fillInt(int8_t val) {
		rec.i8 = val;
	}
	void fillReal(double val) {
		rec.real = val;
	}
	void fillMessage(char* val) {
		strncpy(&rec.message, val, 40);
	}


	/*
	void recFillStandard()
	{
		rec.src_number64 = 0x0000000000000101ULL;
		rec.dst_number64 = -258ULL;
		rec.number32 = 0x80000001UL;
		rec.number16 = 0x03e8;
		rec.number8_1 = 0x80;
		rec.number8_2 = 0x08;
		rec.number8_3 = 0xe0;
		rec.number8_4 = 0x0e;
		rec.real = 3.1428;
		rec.timestamp = 3900000; //1-1-1970 2:5:0.000 - should be good to use UTC time since this is error prone
		strncpy((char*)(&rec.mac_addr)[0], "\x01\x02\x03\x04\x05\x06", sizeof(rec.mac_addr));
		rec.mpls_stack_label[0] = 0x000000fb;
		//strncpy((char*)(&rec.mpls_stack_label)[0], "\x00\xfb", sizeof(rec.mpls_stack_label));	// label is 15, exp is 5, eos is 1
		inet_pton(AF_INET, "192.168.0.1", &rec.ip_addrv4);
		inet_pton(AF_INET6, "fe80::e6f8:9cff:fedc:5b77", &rec.ip_addrv6);
		strncpy(&rec.message[0],"http://youtube.com/index", sizeof(rec.message));
		strncpy(&rec.binary_heap[0],"\x0a\x0d\xff", sizeof(rec.binary_heap));
	}*/

};

/**
 *  \brief Helper macros to shorten parameter list and better readability
 */
#define ff_init(str) ff_init(&filter, str, test_callbacks)
#define ff_eval(rec) ff_eval(filter, (void*(rec))

TEST_F(filter_types_test, integer_test) {
	fillInt(10LL);	
	
	EXPECT_EQ(FF_OK, ff_init("int 10"));
	ASSERT_TRUE(ff_eval(&rec));
	
}

