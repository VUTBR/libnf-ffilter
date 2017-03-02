//
// Created by istoffa on 17.8.2016.
//
#include <gtest/gtest.h>
#include <cstdint>
#include <iostream>
#include <arpa/inet.h>

extern "C" {
#include "profiles/ffilter.h"
#include "profiles/ffilter_internal.h"
}

int main(int argc, char** argv) {
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}



class str_to_number_test : public :: testing::Test {
protected:
	virtual void SetUp() {
		ptr = NULL;
		size = 0;
	}
	virtual void TearDown() {
	}

	void convert_int(int64_t expect, char* valstr, ff_type_t int_size)
	{
		ASSERT_FALSE(str_to_int(NULL, valstr, int_size, &ptr, &size)) << "Failed to convert \""
																	  << valstr << "\" to int";
		//Data has correct length
		EXPECT_EQ(sizeof(int64_t), size) << "Size mismatch \""
										 << valstr << "\"";
		//And compare results
		EXPECT_EQ(expect, *((int64_t *) ptr)) << "Unexpected result of conversion";
		free(ptr);
		return;
	}
	void convert_uint(uint64_t expect, char* valstr, ff_type_t uint_size)
	{
		ASSERT_FALSE(str_to_uint(NULL, valstr, uint_size, &ptr, &size)) << "Failed to convert \""
																		<< valstr << "\" to unsigned int";
		//Data has correct length
		EXPECT_EQ(sizeof(uint64_t), size) << "Size mismatch \""
										  << valstr << "\"";
		//And compare results
		EXPECT_EQ(expect, *((uint64_t *) ptr)) << "Unexpected result of conversion";
		free(ptr);
		return;
	}

	void convert_real(ff_double_t expect, char* valstr)
	{
		ASSERT_FALSE(str_to_real(NULL, valstr, &ptr, &size)) << "Failed to convert \""
															 << valstr << "\" to real";
		//Data has correct length
		EXPECT_EQ(sizeof(double), size) << "Size mismatch \""
										<< valstr << "\"";
		//And compare results
		EXPECT_EQ(expect, *((double *) ptr)) << "Unexpected result of conversion";
		free(ptr);
		return;
	}

	char *ptr;
	size_t size;
};

class str_to_addr_test : public :: testing::Test {
protected:
	virtual void SetUp() {
		ptr = NULL;
		size = 0;
		addrstr[0] = 0;
		maskstr[0] = 0;
	}
	virtual void TearDown() {
	}

	void addr_to_str(ff_net_t* addr, char *addrstr)
	{
		if(addr->ver == 4 && inet_ntop(AF_INET, &addr->ip.data[3], addrstr, addrstr_len)) {
			inet_ntop(AF_INET, &addr->mask.data[3], maskstr, addrstr_len);
		} else if(inet_ntop(AF_INET6, &addr->ip.data[0], addrstr, addrstr_len)) {
			inet_ntop(AF_INET6, &addr->mask.data[0], maskstr, addrstr_len);
		} else { FAIL() << "Address->string conversion failed";}
	}


	void convert_addr(char* valstr, char* expect_addr, char* expect_mask)
	{
		ASSERT_FALSE(str_to_addr(NULL, valstr, &ptr, &size)) << "Conversion failed for \"" << valstr << "\"";
		EXPECT_EQ((sizeof(ff_net_t)), size);
		addr_to_str(((ff_net_t*)ptr), &addrstr[0]);
		ASSERT_STREQ(expect_addr, addrstr) << "Unexpected result of ip conversion";
		ASSERT_STREQ(expect_mask, maskstr) << "Unexpected result of mask conversion";
		free(ptr);

		return;
	}

	void not_convert_addr(char* valstr) {
		int x;
		EXPECT_TRUE(x = str_to_addr(NULL, valstr, &ptr, &size)) << "Conversion should not succeed for " << valstr;
		if(!x) free(ptr);
	}

	static const int addrstr_len = 40;
	char *ptr;
	size_t size;
	char addrstr[addrstr_len];
	char maskstr[addrstr_len];
};

class str_to_mac_test : public :: testing::Test {
protected:
	virtual void SetUp() {
		ptr = NULL;
		size = 0;
		addrstr[0] = 0;
	}

	virtual void TearDown() {
	}

	void convert_mac(char* mac, char* expect_mac)
	{
		return;
	}

	char *ptr;
	size_t size;
	char addrstr[40];
};


/**
 * Check conversion function
 */
TEST_F(str_to_number_test, unsigned_int_valid) {

	convert_uint(0, "0", FF_TYPE_UINT64);
	convert_uint(1000, "1k", FF_TYPE_UINT64);
	convert_uint(1000000, "1 M", FF_TYPE_UINT64);
	convert_uint(UINT16_MAX, "65535", FF_TYPE_UINT64);
	convert_uint(UINT32_MAX, "4294967295", FF_TYPE_UINT64);
	convert_uint(1234567890000000000ULL, "1234567890 G", FF_TYPE_UINT64);
	convert_uint(UINT64_MAX, "18446744073709551615", FF_TYPE_UINT64);
	convert_uint(0xff, "0xff", FF_TYPE_UINT64);
	convert_uint(0x3f, "077", FF_TYPE_UINT64);

}

TEST_F(str_to_addr_test, ipv4_valid)
{
	/*           Tested string - Expected ip - Expected mask  */
	convert_addr("192.168.0.25/4", "192.0.0.0", "240.0.0.0");
	convert_addr("192.168/10", "192.128.0.0", "255.192.0.0");
	convert_addr("255/4", "240.0.0.0", "240.0.0.0");
}

TEST_F(str_to_addr_test, ipv4_invalid) {

	not_convert_addr("22.0 .10");
	not_convert_addr("192.168.0.0/33");
	not_convert_addr("929-323-098");
	not_convert_addr("192.168. 0.0");
	not_convert_addr("192.168 .0.0");
}

TEST_F(str_to_addr_test, ipv6_valid) {
	convert_addr("2001:608::/15", "2000::", "fffe::");

}
TEST_F(str_to_addr_test, invalid_numeric_mask){

	not_convert_addr("192.168.0.0/-1");
	not_convert_addr("192.168.0.0/33");
	not_convert_addr("::127/-1");
	not_convert_addr("::127/129");
}

/**
 * Conversion should fail given bad input
 */
TEST_F(str_to_number_test, unsigned_invalid_number_conversion) {

	char numbers[][30] = {
		"-+1",
		"1kT",		//Fail if two units
		"10f M",	//Fail if has sign in number
		"1e10",		//Fail if scientific number
		"deadbeef",	//Fail if hexa is without prefix
		"-922337203685477580 M8 ", //Fail if unit is not last sign in number
		""
	};

	for (int x = 0; numbers[x][0] ; x++) {
		//Conversion should fail
		EXPECT_TRUE(str_to_uint(NULL, numbers[x], FF_TYPE_UINT64, &ptr, &size )) <<
			"Conversion to number " << x <<  ". \"" << numbers[x] << "\" should fail";
	}

}

/**
 * Large numbers are trimmed to max range if string contains too bg number
 */
TEST_F(str_to_number_test, unsigned_large_number_trimm) {

	char number[] = "18446744073709551615";

	EXPECT_EQ(0, str_to_uint(NULL, number, FF_TYPE_UINT32, &ptr, &size )) <<
		"Failed to convert test number" <<"\"" << number << "\"";

	EXPECT_EQ(size, sizeof(uint32_t));

	EXPECT_EQ(UINT32_MAX, *((uint32_t *)ptr));

}

/**
 * Max range check for signed integers
 */
TEST_F(str_to_number_test, signed_valid_max_range){

	//Check max range numbers
	ASSERT_EQ(0, str_to_int(NULL, "-9223372036854775808", FF_TYPE_INT64, &ptr, &size));
	EXPECT_EQ((sizeof(int64_t)), size);
	ASSERT_EQ((INT64_MIN), *((uint64_t *)ptr));

	ASSERT_EQ(0, str_to_int(NULL, "9223372036854775807", FF_TYPE_INT64, &ptr, &size));
	EXPECT_EQ((sizeof(int64_t)), size);
	ASSERT_EQ((INT64_MAX), *((uint64_t *)ptr));

}

/**
 * Range check on out of range numbers, rasults are to be trimmed
 */
TEST_F(str_to_number_test, int_invalid_range) {

	//Try convert over max uint64 range numbers
	ASSERT_EQ(0, str_to_int(NULL, "-9223372036854775809", FF_TYPE_INT64, &ptr, &size));
	EXPECT_EQ((sizeof(int64_t)), size);

	ASSERT_EQ((INT64_MIN), *((uint64_t *)ptr));
	free(ptr);

	ASSERT_EQ(0, str_to_int(NULL, "9223372036854775808", FF_TYPE_INT64, &ptr, &size));
	EXPECT_EQ((sizeof(int64_t)), size);

	ASSERT_EQ((INT64_MAX), *((uint64_t *)ptr));
	//Results should be trimmed
}


/**
 * Check address conversion on regular ipv6 without mask
 */
TEST_F(str_to_addr_test, addrV6_full_valid) {

	ASSERT_EQ(0, str_to_addr(NULL, "2001:608::0", &ptr, &size));
	EXPECT_EQ((sizeof(ff_net_t)), size);
	//Address to be marked as ipv6

	inet_ntop(AF_INET6, &(((ff_net_t*)ptr)->ip.data[0]), addrstr, 40);

	ASSERT_STREQ("2001:608::", addrstr);
	free(ptr);

	ASSERT_EQ(0, str_to_addr(NULL, "2001:608:0:f:f:f:f:1", &ptr, &size));
	EXPECT_EQ((sizeof(ff_net_t)), size);

	inet_ntop(AF_INET6, &(((ff_net_t*)ptr)->ip.data[0]), addrstr, 40);

	ASSERT_STREQ("2001:608:0:f:f:f:f:1", addrstr);
	free(ptr);
}

/**
 * Mask generation mechanism int_to_netmask
 */
TEST_F(str_to_addr_test, addrV4_full_valid_numeric_mask) {

	ASSERT_EQ(0, str_to_addr(NULL, "192.168.0.1/10", &ptr, &size));
	EXPECT_EQ((sizeof(ff_net_t)), size);

	inet_ntop(AF_INET, &(((ff_net_t*)ptr)->ip.data[3]), addrstr, 40);

	ASSERT_STREQ("192.128.0.0", addrstr);
	free(ptr);

	ASSERT_EQ(0, str_to_addr(NULL, "255.255.255.255/17", &ptr, &size));
	EXPECT_EQ((sizeof(ff_net_t)), size);

	inet_ntop(AF_INET, &(((ff_net_t*)ptr)->ip.data[3]), addrstr, 40);

	ASSERT_STREQ("255.255.128.0", addrstr);
	free(ptr);

}

/**
 * Ip autocompletion test
 */
TEST_F(str_to_addr_test, addrV4_short_valid_numeric_mask) {

	ASSERT_EQ(0, str_to_addr(NULL, "192.168/10", &ptr, &size));
	EXPECT_EQ((sizeof(ff_net_t)), size);

	inet_ntop(AF_INET, &(((ff_net_t*)ptr)->ip.data[3]), addrstr, 40);

	ASSERT_STREQ("192.128.0.0", addrstr);
	free(ptr);

	ASSERT_EQ(0, str_to_addr(NULL, "255.255.255/17", &ptr, &size));
	EXPECT_EQ((sizeof(ff_net_t)), size);

	inet_ntop(AF_INET, &(((ff_net_t*)ptr)->ip.data[3]), addrstr, 40);

	ASSERT_STREQ("255.255.128.0", addrstr);

	free(ptr);
}

/**
 * Mask ip with full mask conversion test
 */
TEST_F(str_to_addr_test, addrV4_valid_mask) {

	ASSERT_EQ(0, str_to_addr(NULL, "192.168.0.0 255.0.0.0", &ptr, &size));
	EXPECT_EQ((sizeof(ff_net_t)), size);
	inet_ntop(AF_INET, &(((ff_net_t*)ptr)->ip.data[3]), addrstr, 40);

	ASSERT_STREQ("192.0.0.0", addrstr);
	free(ptr);

	ASSERT_EQ(0, str_to_addr(NULL, "255.255.0.0 255.128.0.0", &ptr, &size));
	EXPECT_EQ((sizeof(ff_net_t)), size);

	inet_ntop(AF_INET, &(((ff_net_t*)ptr)->ip.data[3]), addrstr, 40);

	ASSERT_STREQ("255.128.0.0", addrstr);

}

/**
 * Conversion of valid mac
 */
TEST_F(str_to_mac_test, valid_mac) {

	char mac[] = "02:ff:de:ad:be:ef";

	ASSERT_EQ(0, str_to_mac(NULL, mac, &ptr, &size));
	EXPECT_EQ(sizeof(ff_mac_t), size);
	snprintf(addrstr, 40,"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);

	ASSERT_STRCASEEQ(mac, addrstr);
}

/**
 * Conversion of invalid mac
 */
TEST_F(str_to_mac_test, invalid_mac) {

	char mac[] = "02:fff:de:ad:be:ef";

	EXPECT_EQ(1, str_to_mac(NULL, mac, &ptr, &size));

	char mac2[] = "02:ff:de:ad:be:ef:ed";

	EXPECT_EQ(1, str_to_mac(NULL, mac2, &ptr, &size));
}

TEST_F(str_to_number_test, real_number) {

	char number[] = "-10.0e-3";

	ASSERT_EQ(0, str_to_real(NULL, number, &ptr, &size));
	ASSERT_EQ(-10.0e-3,  *((double *)ptr));
}

TEST_F(str_to_number_test, invalid_real) {
	int x;
	x = str_to_real(NULL, "092238.39ffs.e", &ptr, &size);
	EXPECT_TRUE(x);
	if (!x) free(ptr);
}