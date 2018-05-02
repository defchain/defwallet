/*
 * sha3.h
 *
 * Created on: Apr 20, 2018
 * Author: happyliu
 */
#pragma once

#ifndef SHA3_H_
#define SHA3_H_

#include <iostream>
#include <stdio.h>
#include <cstdint>
#include <array>
#include <vector>
#include <algorithm>
#include <cstring>
#include <string>

#define decsha3(bits) \
	int sha3_##bits(uint8_t*, size_t, uint8_t const*, size_t);

decsha3(256)
decsha3(512)
static inline void SHA3_256(uint8_t* ret, const uint8_t * data, size_t const size)
{
	sha3_256(ret, 32, data, size);
}
static inline void SHA3_512(uint8_t* ret, uint8_t const* data, size_t const size)
{
	sha3_512(ret, 64, data, size);
}

/*
 *	以太坊sha3-256
 *	参数为vector
 */
bool ethsha3(std::vector<uint8_t> _input, std::vector<uint8_t>& o_output);

/*
 *	以太坊sha3-256
 *	参数为array
 */
bool ethsha3(std::array<uint8_t, 64> _input, std::array<uint8_t, 32>& o_output);


/*
*	以太坊sha3-256
*	参数为std::string
*/
bool ethsha3(std::string _input, std::array<uint8_t, 32>& o_output);


/*
*	以太坊sha3-256
*	参数为std::string
*/
bool ethsha3(std::string _input, std::vector<uint8_t>& o_output);


/*
 *	对字符串进行sha3_256
 */
std::string sha3_256(std::string input);



/**
* 返回16进制字符串s对应的整数值，遇到任何一个非法字符都返回-1 空字符串返回0

* e.g.
* char* p = "0a";
* hexToDec(p);
*/
inline int hexToDec(const char *s)
{
	const char *p = s;

	//空串返回0
	if (*p == '\0') { return 0; }

	//忽略开头的'0'字符
	while (*p == '0') { p++; }

	int dec = 0;
	char c;

	//循环直到字符串结束。
	while (c = *(p++))
	{
		//dec乘16
		dec <<= 4;

		//数字字符
		if (c >= '0' && c <= '9')
		{
			dec += c - '0';
			continue;
		}

		//小写abcdef
		if (c >= 'a' && c <= 'f')
		{
			dec += c - 'a' + 10;
			continue;
		}

		//大写ABCDEF
		if (c >= 'A' && c <= 'F')
		{
			dec += c - 'A' + 10;
			continue;
		}

		//没有从任何一个if语句中结束，说明遇到了非法字符
		return -1;
	}

	//正常结束循环，返回10进制整数值
	return dec;
}

#endif /* SHA3_H_ */
