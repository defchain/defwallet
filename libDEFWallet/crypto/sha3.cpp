/*
 * sha3.cpp
 *
 * Created on: Apr 20, 2018
 * Author: happyliu
 */
#include <iostream>
#include <stdio.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "sha3.h"


/** libkeccak-tiny
*
* A single-file implementation of SHA-3 and SHAKE.
*
* Implementor: David Leon Gil
* License: CC0, attribution kindly requested. Blame taken too,
* but not liability.
*/

#define decshake(bits) \
  int shake##bits(uint8_t*, size_t, const uint8_t*, size_t);

decshake(128)
decshake(256)
decsha3(224)
decsha3(256)
decsha3(384)
decsha3(512)

/******** The Keccak-f[1600] permutation ********/

/*** Constants. ***/
static const uint8_t rho[24] = \
{ 1, 3, 6, 10, 15, 21,
28, 36, 45, 55, 2, 14,
27, 41, 56, 8, 25, 43,
62, 18, 39, 61, 20, 44};
static const uint8_t pi[24] = \
{10, 7, 11, 17, 18, 3,
5, 16, 8, 21, 24, 4,
15, 23, 19, 13, 12, 2,
20, 14, 22, 9, 6, 1};
static const uint64_t RC[24] = \
{1ULL, 0x8082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
0x808bULL, 0x80000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
0x8aULL, 0x88ULL, 0x80008009ULL, 0x8000000aULL,
0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
0x8000000000008002ULL, 0x8000000000000080ULL, 0x800aULL, 0x800000008000000aULL,
0x8000000080008081ULL, 0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL};

/*** Helper macros to unroll the permutation. ***/
#define rol(x, s) (((x) << s) | ((x) >> (64 - s)))
#define REPEAT6(e) e e e e e e
#define REPEAT24(e) REPEAT6(e e e e)
#define REPEAT5(e) e e e e e
#define FOR5(v, s, e) \
  v = 0;            \
  REPEAT5(e; v += s;)

/*** Keccak-f[1600] ***/
static inline void keccakf(void* state) {
	uint64_t* a = (uint64_t*)state;
	uint64_t b[5] = { 0 };
	uint64_t t = 0;
	uint8_t x, y;

	for (int i = 0; i < 24; i++) {
		// Theta
		FOR5(x, 1,
			b[x] = 0;
		FOR5(y, 5,
			b[x] ^= a[x + y]; ))
			FOR5(x, 1,
				FOR5(y, 5,
					a[y + x] ^= b[(x + 4) % 5] ^ rol(b[(x + 1) % 5], 1); ))
			// Rho and pi
			t = a[1];
		x = 0;
		REPEAT24(b[0] = a[pi[x]];
		a[pi[x]] = rol(t, rho[x]);
		t = b[0];
		x++; )
			// Chi
			FOR5(y,
				5,
				FOR5(x, 1,
					b[x] = a[y + x];)
				FOR5(x, 1,
					a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]); ))
			// Iota
			a[0] ^= RC[i];
	}
}

/******** The FIPS202-defined functions. ********/

/*** Some helper macros. ***/

#define _(S) do { S } while (0)
#define FOR(i, ST, L, S) \
  _(for (size_t i = 0; i < L; i += ST) { S; })
#define mkapply_ds(NAME, S)                                          \
  static inline void NAME(uint8_t* dst,                              \
						  const uint8_t* src,                        \
						  size_t len) {                              \
	FOR(i, 1, len, S);                                               \
  }
#define mkapply_sd(NAME, S)                                          \
  static inline void NAME(const uint8_t* src,                        \
						  uint8_t* dst,                              \
						  size_t len) {                              \
	FOR(i, 1, len, S);                                               \
  }

mkapply_ds(xorin, dst[i] ^= src[i])  // xorin
mkapply_sd(setout, dst[i] = src[i])  // setout

#define P keccakf
#define Plen 200

									 // Fold P*F over the full blocks of an input.
#define foldP(I, L, F) \
  while (L >= rate) {  \
	F(a, I, rate);     \
	P(a);              \
	I += rate;         \
	L -= rate;         \
  }

									 /** The sponge-based hash construction. **/
	static inline int hash(uint8_t* out, size_t outlen,
		const uint8_t* in, size_t inlen,
		size_t rate, uint8_t delim) {
	if ((out == NULL) || ((in == NULL) && inlen != 0) || (rate >= Plen)) {
		return -1;
	}
	uint8_t a[Plen] = { 0 };
	// Absorb input.
	foldP(in, inlen, xorin);
	// Xor in the DS and pad frame.
	a[inlen] ^= delim;
	a[rate - 1] ^= 0x80;
	// Xor in the last block.
	xorin(a, in, inlen);
	// Apply P
	P(a);
	// Squeeze output.
	foldP(out, outlen, setout);
	setout(a, out, outlen);
	memset(a, 0, 200);
	return 0;
}

/*** Helper macros to define SHA3 and SHAKE instances. ***/
#define defshake(bits)                                            \
  int shake##bits(uint8_t* out, size_t outlen,                    \
				  const uint8_t* in, size_t inlen) {              \
	return hash(out, outlen, in, inlen, 200 - (bits / 4), 0x1f);  \
  }
#define defsha3(bits)                                             \
  int sha3_##bits(uint8_t* out, size_t outlen,                    \
				  const uint8_t* in, size_t inlen) {              \
	if (outlen > (bits/8)) {                                      \
	  return -1;                                                  \
	}                                                             \
	return hash(out, outlen, in, inlen, 200 - (bits / 4), 0x01);  \
  }

/*** FIPS202 SHAKE VOFs ***/
defshake(128)
defshake(256)

/*** FIPS202 SHA3 FOFs ***/
defsha3(224)
defsha3(256)
defsha3(384)
defsha3(512)


/*
*	以太坊sha3-256
*	参数为vector
*/
bool ethsha3(std::vector<uint8_t> _input, std::vector<uint8_t>& o_output)
{
	if (o_output.size() != 32)
		return false;
	sha3_256(o_output.data(), 32, _input.data(), _input.size());
	return true;
}

/*
*	以太坊sha3-256
*	参数为array
*/
bool ethsha3(std::array<uint8_t, 64> _input, std::array<uint8_t, 32>& o_output)
{
	if (o_output.size() != 32)
		return false;
	sha3_256(o_output.data(), 32, _input.data(), _input.size());
	return true;
}


/*
*	以太坊sha3-256
*	参数为std::string + array
*/
bool ethsha3(std::string _input, std::array<uint8_t, 32>& o_output)
{
	if (_input.size() == 0) {
		return false;
	}

	std::string tmpstr;
	std::array<uint8_t, 64> tmp_pubarr = { 0 };
	for (int i = 0; i< 64; i++) {
		tmpstr = _input.substr(i * 2, 2);
		char* p = (char*)tmpstr.c_str();
		tmp_pubarr[i] = hexToDec(p);
	}

	return ::ethsha3(tmp_pubarr, o_output);
}

/*
*	以太坊sha3-256
*	参数为std::string + vector
*/
bool ethsha3(std::string _input, std::vector<uint8_t>& o_output)
{
	if (_input.size() == 0) {
		return false;
	}
	std::string tmpstr;
	std::vector<uint8_t> tmp_pubarr(64);
	for (int i = 0; i< 64; i++) {
		tmpstr = _input.substr(i * 2, 2);
		char* p = (char*)tmpstr.c_str();
		tmp_pubarr[i] = hexToDec(p);
	}

	return ::ethsha3(tmp_pubarr, o_output);
}

/*
*	对字符串进行sha3_256
*/
std::string sha3_256(std::string input)
{
	uint8_t output[32];
	char outputHex[65];

	SHA3_256(output, (const uint8_t*)input.c_str(), input.size());

	for (int i = 0; i<32; i++) {
		sprintf(&outputHex[i * 2], "%02X", output[i]);
	}

	return std::string(outputHex, 64);
}
