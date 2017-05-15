//
// Created by istoffa on 22.8.2016.
//

#include <gtest/gtest.h>
#include <arpa/inet.h>

extern "C" {
#include "ffilter.h"

}

//TODO: Test ffilter interface
int main(int argc, char** argv) {
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

/**
 *	\struct test_record
 *	\briref data record mockup structure
 */
struct test_record {
	uint64_t src_number64;
	uint64_t dst_number64;
	uint32_t number32;
	uint16_t number16;
	uint8_t	 number8_1;
	uint8_t  number8_2;
	uint8_t  number8_3;
	uint8_t  number8_4;
	double   real;
	ff_mac_t mac_addr;
	ff_mpls_t mpls_stack_label;
	uint32_t ip_addrv4;
	ff_ip_t  ip_addrv6;
	uint64_t timestamp;
	char message[64];
	char binary_heap[64];
};

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

	if 	      (!strcmp(valstr, "uint")) { type = FF_TYPE_UNSIGNED;
		lvalue->id[0].index = FLD_SRC_NUMBER64;
		lvalue->id[1].index = FLD_DST_NUMBER64;
		lvalue->options |= FF_OPTS_MULTINODE;

	} else if (!strcmp(valstr, "srcuint")) { type = FF_TYPE_UNSIGNED;
		lvalue->id[0].index = FLD_SRC_NUMBER64;

	} else if (!strcmp(valstr, "dstuint")) { type = FF_TYPE_UNSIGNED;
		lvalue->id[0].index = FLD_DST_NUMBER64;

	} else if (!strcmp(valstr, "ui64")) { type = FF_TYPE_UINT64;
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

	} else if (!strcmp(valstr, "srcint")) { type = FF_TYPE_SIGNED;
		lvalue->id[0].index = FLD_SRC_NUMBER64;

	} else if (!strcmp(valstr, "dstint")) { type = FF_TYPE_SIGNED;
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
 * which was set by lookup callback \see test_lookup_func. Buffer always
 * contains pointer to data, size contains length of valid data.
 * @param filter
 * @param rec test_record reference
 * @param extid Ident. of field
 * @param buf Selected reference copied here, also makes place for data to copy to if necessary
 * @param size Length of selected data
 * @return FF_OK on data copied
 */
ff_error_t test_data_func (struct ff_s *filter, void *rec, ff_extern_id_t extid, char* buf, size_t *size)
{
	struct test_record *trec = (struct test_record*)rec;

	char *data;

	switch(extid.index) {
	case FLD_SRC_NUMBER64:
		 data = (char*)&trec->src_number64; *size = sizeof(uint64_t); break;
	case FLD_DST_NUMBER64:
		 data = (char*)&trec->dst_number64; *size = sizeof(uint64_t); break;
	case FLD_NUMBER32:
		 data = (char*)&trec->number32; *size = sizeof(uint32_t);break;
	case FLD_NUMBER16:
		 data = (char*)&trec->number16; *size = sizeof(uint16_t);break;
	case FLD_NUMBER8_1:
		 data = (char*)&trec->number8_1; *size = sizeof(uint8_t);break;
	case FLD_NUMBER8_2:
		 data = (char*)&trec->number8_2; *size = sizeof(uint8_t);break;
	case FLD_NUMBER8_3:
		 data = (char*)&trec->number8_3; *size = sizeof(uint8_t);break;
	case FLD_NUMBER8_4:
		 data = (char*)&trec->number8_4; *size = sizeof(uint8_t);break;
	case FLD_REAL:
		 data = (char*)&trec->real; *size = sizeof(double);break;
	case FLD_MAC_ADDR:
		 data = (char*)&trec->mac_addr; *size = sizeof(ff_mac_t);break;
//	case FLD_MPLS_STACK_LABEL:
		 data = (char*)&trec->mpls_stack_label; *size = sizeof(uint32_t);break;
	case FLD_IP_ADDRV4:
		 data = (char*)&trec->ip_addrv4; *size = sizeof(uint32_t);break;
	case FLD_IP_ADDRV6:
		 data = (char*)&trec->ip_addrv6; *size = sizeof(ff_ip_t);break;
	case FLD_TIMESTAMP:
		 data = (char*)&trec->timestamp; *size = sizeof(uint64_t);break;
	case FLD_MESSAGE:
		 data = &trec->message[0]; *size = strlen(&trec->message[0]);break;
	case FLD_BINARY_HEAP: data = &trec->binary_heap[0]; *size = sizeof(&trec->binary_heap);
		break;
	case FLD_NONE:
	default : *size = 0; return FF_ERR_OTHER;
	}

	*(char**)buf = data;
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


class ffilter_interface_test : public :: testing::Test {
protected:
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
	}

	char *expr;
	struct test_record rec;
	ff_options_t* test_callbacks;
	ff_t *filter;
	char *buffer;
};

/*
 * Test for fields uint, src uint, dst uint, ui64, ui32, ui16, ui8 and signed variants
 * int, src int, dst int, i64, i32, i16, i8
 */
TEST_F(ffilter_interface_test, integer_datatypes)
{
	recFillStandard();

	char *expr = NULL;
	ASSERT_EQ(FF_OK, ff_init(&filter, expr="ui8 0x80", test_callbacks)) << ff_error(filter, buffer, FF_MAX_STRING);
	ASSERT_TRUE(ff_eval(filter, (void*)&rec)) << "Eval failed for \"" << expr << "\""; ff_free(filter);

	ASSERT_EQ(FF_OK, ff_init(&filter, expr="i8 -128", test_callbacks)) << ff_error(filter, buffer, FF_MAX_STRING);
	ASSERT_TRUE(ff_eval(filter, (void*)&rec)) << "Eval failed for \"" << expr << "\""; ff_free(filter);

	ASSERT_EQ(FF_OK, ff_init(&filter, expr="i16 1000", test_callbacks)) << ff_error(filter, buffer, FF_MAX_STRING);
	ASSERT_TRUE(ff_eval(filter, (void*)&rec)) << "Eval failed for \"" << expr << "\""; ff_free(filter);

	ASSERT_EQ(FF_OK, ff_init(&filter, expr="i32 < 0", test_callbacks)) << ff_error(filter, buffer, FF_MAX_STRING);
	ASSERT_TRUE(ff_eval(filter, (void*)&rec)) << "Eval failed for \"" << expr << "\""; ff_free(filter);

	ASSERT_EQ(FF_OK, ff_init(&filter, expr="ui32 < 0", test_callbacks)) << ff_error(filter, buffer, FF_MAX_STRING);
	ASSERT_FALSE(ff_eval(filter, (void*)&rec)) << "Eval failed for \"" << expr << "\""; ff_free(filter);

	ASSERT_EQ(FF_OK, ff_init(&filter, expr="src int > 0", test_callbacks)) << ff_error(filter, buffer, FF_MAX_STRING);
	ASSERT_TRUE(ff_eval(filter, (void*)&rec)) << "Eval failed for \"" << expr << "\""; ff_free(filter);

	ASSERT_EQ(FF_OK, ff_init(&filter, expr="dst uint > 0", test_callbacks)) << ff_error(filter, buffer, FF_MAX_STRING);
	ASSERT_TRUE(ff_eval(filter, (void*)&rec)) << "Eval failed for \"" << expr << "\""; ff_free(filter);

	ASSERT_EQ(FF_OK, ff_init(&filter, expr="dst int > 0", test_callbacks)) << ff_error(filter, buffer, FF_MAX_STRING);
	ASSERT_FALSE(ff_eval(filter, (void*)&rec)) << "Eval failed for \"" << expr << "\""; ff_free(filter);
}


/* Advanced features */
TEST_F(ffilter_interface_test, multinode)
{
	recFillStandard();

	char *expr = NULL;

	ASSERT_EQ(FF_OK, ff_init(&filter, expr="int -258", test_callbacks)) << ff_error(filter, buffer, FF_MAX_STRING);
	ASSERT_TRUE(ff_eval(filter, (void*)&rec)) << "Eval failed for \"" << expr << "\""; ff_free(filter);

	/* ui8Multinode checks for 4 different variables for value  */
	ASSERT_EQ(FF_OK, ff_init(&filter, expr="ui8Multinode 0x08", test_callbacks)) << ff_error(filter, buffer, FF_MAX_STRING);
	ASSERT_TRUE(ff_eval(filter, (void*)&rec)) << "Eval failed for \"" << expr << "\""; ff_free(filter);

}

TEST_F(ffilter_interface_test, multinode_in)
{
	recFillStandard();

	char *expr = NULL;

	ASSERT_EQ(FF_OK, ff_init(&filter, expr="ui8Multinode in [ 0x08 0xe0 0x0e ]", test_callbacks)) << ff_error(filter, buffer, FF_MAX_STRING);
	ASSERT_TRUE(ff_eval(filter, (void*)&rec)) << "Eval failed for \"" << expr << "\""; ff_free(filter);

	//Catch semantic error
	ASSERT_NE(FF_OK, ff_init(&filter, expr="ui8Multinode in [ 0x08 0xe0 ix0e ]", test_callbacks)) << ff_error(filter, buffer, FF_MAX_STRING);

}

TEST_F(ffilter_interface_test, translation)
{
	ASSERT_EQ(FF_OK, ff_init(&filter, expr="i16 kilobyte", test_callbacks)) << ff_error(filter, buffer, FF_MAX_STRING);
	ASSERT_TRUE(ff_eval(filter, (void*)&rec)) << "Eval failed for \"" << expr << "\""; ff_free(filter);
}

TEST_F(ffilter_interface_test, real)
{
	recFillStandard();

	char *expr = NULL;

	ASSERT_EQ(FF_OK, ff_init(&filter, expr = "real < 15 and real > 0", test_callbacks));
	ASSERT_TRUE(ff_eval(filter, (void*)&rec));
}

TEST_F(ffilter_interface_test, mac_eq)
{
	recFillStandard();

	char *expr = NULL;
	ASSERT_EQ(FF_OK, ff_init(&filter, expr = "mac 01:02:03:04:05:06", test_callbacks));
	ASSERT_TRUE(ff_eval(filter, (void*)&rec));

	ASSERT_EQ(FF_OK, ff_init(&filter, expr = "mac = 06:05:04:03:02:01", test_callbacks));
	ASSERT_FALSE(ff_eval(filter, (void*)&rec));

	ASSERT_EQ(FF_OK, ff_init(&filter, expr = "mac = 01:02:03:04:05:f6", test_callbacks));
	ASSERT_FALSE(ff_eval(filter, (void*)&rec));

}


TEST_F(ffilter_interface_test, mplslabel_eq)
{
	recFillStandard();

	char *expr = NULL;
	//TODO: implement internal type
	ASSERT_EQ(FF_OK, ff_init(&filter, expr = "mplsLabel 15", test_callbacks));
	ASSERT_TRUE(ff_eval(filter, (void*)&rec));

	ASSERT_EQ(FF_OK, ff_init(&filter, expr = "mplsEos 1", test_callbacks));
	ASSERT_TRUE(ff_eval(filter, (void*)&rec));

	ASSERT_EQ(FF_OK, ff_init(&filter, expr = "mplsExp 5", test_callbacks));
	ASSERT_TRUE(ff_eval(filter, (void*)&rec));
}


TEST_F(ffilter_interface_test, ipv4)
{
	recFillStandard();

	ASSERT_EQ(FF_OK, ff_init(&filter, expr ="v4addr 192.168.0.1", test_callbacks));
	ASSERT_TRUE(ff_eval(filter, (void*)&rec)); ff_free(filter);

	ASSERT_EQ(FF_OK, ff_init(&filter, "v4addr 192.0.0.0 240.0.0.0", test_callbacks));
	ASSERT_TRUE(ff_eval(filter, (void*)&rec)); ff_free(filter);

	ASSERT_EQ(FF_OK, ff_init(&filter, "v6addr 2010::/16", test_callbacks));
	ASSERT_FALSE(ff_eval(filter, (void*)&rec)); ff_free(filter);
}

TEST_F(ffilter_interface_test, ipv4_slash_mask)
{
	recFillStandard();
	ASSERT_EQ(FF_OK, ff_init(&filter, "v4addr 192.128/10 ", test_callbacks));
	ASSERT_TRUE(ff_eval(filter, (void*)&rec)); ff_free(filter);

	ASSERT_NE(FF_OK, ff_init(&filter, "v4addr 192.128/24", test_callbacks));

	ASSERT_NE(FF_OK, ff_init(&filter, "v4addr 192.128.0.1/33 ", test_callbacks));
}

TEST_F(ffilter_interface_test, ipv6_slash_mask)
{
	recFillStandard();

	ASSERT_EQ(FF_OK, ff_init(&filter, "v6addr fe80::e6f8:9cff:fedc:5b77", test_callbacks));
	ASSERT_TRUE(ff_eval(filter, (void*)&rec)); ff_free(filter);

	ASSERT_EQ(FF_OK, ff_init(&filter, "v6addr fe80::/16", test_callbacks));
	ASSERT_TRUE(ff_eval(filter, (void*)&rec)); ff_free(filter);

	ASSERT_NE(FF_OK, ff_init(&filter, "v6addr fe80::/129", test_callbacks));
}


TEST_F(ffilter_interface_test, timestamp)
{
	recFillStandard();

	ASSERT_EQ(FF_OK, ff_init(&filter, expr = "timestamp > 1970-1-1 01:00:00 and timestamp < 1970-1-1 02:10:0", test_callbacks));
	ASSERT_TRUE(ff_eval(filter, (void*)&rec)); ff_free(filter);

	ASSERT_EQ(FF_OK, ff_init(&filter, expr = "timestamp 1970-1-1 02:05:00", test_callbacks));
	ASSERT_TRUE(ff_eval(filter, (void*)&rec)); ff_free(filter);
}


TEST_F(ffilter_interface_test, string_eq)
{
	recFillStandard();

	ASSERT_EQ(FF_OK, ff_init(&filter, expr="message = http://youtube.com/index", test_callbacks));
	ASSERT_TRUE(ff_eval(filter, (void*)&rec));

	ASSERT_EQ(FF_OK, ff_init(&filter, expr="message = \"http://youtube.com/index&^$#$@\"", test_callbacks));
	ASSERT_TRUE(ff_eval(filter, (void*)&rec));
}

TEST_F(ffilter_interface_test, string_substring)
{
	recFillStandard();

	ASSERT_EQ(FF_OK, ff_init(&filter, expr="message youtube.com", test_callbacks));
	ASSERT_TRUE(ff_eval(filter, (void*)&rec));
	rec.message[10] = 'x';
	ASSERT_FALSE(ff_eval(filter, (void*)&rec));
}

//TODO: Add negative tests
