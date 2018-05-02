//
//  hd_private.cpp
//  DEFWalletSample
//
//  Created by 成岗 on 2018/4/20.
//  Copyright © 2018年 成岗. All rights reserved.
//

#include "hd_private.hpp"
#include <iostream>
#include "../utils/data_utils.hpp"
#include "../crypto/hmac_sha512.h"
#include "../crypto/secp256k1.h"
#include "assert.h"

namespace libdefwallet
{

static const std::vector<uint8_t> kBitCoinSeed(to_chunk("Bitcoin seed"));

std::vector<uint8_t> merge(std::array<uint8_t, 33> a, std::array<uint8_t, 4> b)
{
    std::vector<uint8_t> out;
    out.reserve(37);
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

std::vector<uint8_t> merge(std::array<uint8_t, 1> a, std::array<uint8_t, 32> b, std::array<uint8_t, 4> c)
{
    std::vector<uint8_t> out;
    out.reserve(37);
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    out.insert(out.end(), c.begin(), c.end());
    return out;
}

template <size_t Size>
using byte_array = std::array<uint8_t, Size>;

template <typename Integer>
byte_array<sizeof(Integer)> to_big_endian(Integer value)
{
    //    VERIFY_UNSIGNED(Integer);
    byte_array<sizeof(Integer)> out;

    for (auto it = out.rbegin(); it != out.rend(); ++it)
    {
        *it = static_cast<uint8_t>(value);
        value >>= 8;
    }

    return out;
}

template <class Iterator>
std::string toHex(Iterator _it, Iterator _end, std::string const &_prefix)
{
    typedef std::iterator_traits<Iterator> traits;
    static_assert(sizeof(typename traits::value_type) == 1, "toHex needs byte-sized element type");

    static char const *hexdigits = "0123456789abcdef";
    size_t off = _prefix.size();
    std::string hex(std::distance(_it, _end) * 2 + off, '0');
    hex.replace(0, off, _prefix);
    for (; _it != _end; _it++)
    {
        hex[off++] = hexdigits[(*_it >> 4) & 0x0f];
        hex[off++] = hexdigits[*_it & 0x0f];
    }
    return hex;
}

std::array<uint8_t, 64> HMAC_SHA512(std::vector<uint8_t> data, std::array<uint8_t, 32> key)
{

    std::array<uint8_t, 64> out;
    HMACSHA512(data.data(), data.size(), key.data(), key.size(), out.data());
    return out;
}

HDPrivate::HDPrivate(std::array<uint8_t, 64> &seeds, uint64_t prefixes)
{

    std::array<uint8_t, 64> masterKey;
    HMACSHA512(seeds.data(), seeds.size(), kBitCoinSeed.data(), kBitCoinSeed.size(), masterKey.data());

    std::copy_n(std::begin(masterKey), 32, privateKey_.begin());
    std::copy_n(std::begin(masterKey) + 32, 32, chainCode_.begin());

    publicKey_ = privateToPublic(privateKey_);
    depth_ = 0;
}

HDPrivate::HDPrivate(std::array<uint8_t, 32> privateKey, std::array<uint8_t, 32> chainCode, unsigned char depth)
{
    this->privateKey_ = privateKey;
    this->publicKey_ = privateToPublic(privateKey);
    this->chainCode_ = chainCode;
    this->depth_ = depth;
}

std::array<uint8_t, 33> HDPrivate::privateToPublic(std::array<uint8_t, 32> privateKey)
{

    //生成主公钥
    const auto ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey pubkey;
    const auto r = secp256k1_ec_pubkey_create(ctx, &pubkey, privateKey.data());
    if (r != 1)
    {
        return {};
    }

    std::array<uint8_t, 33> out;
    size_t size = out.size();
    secp256k1_ec_pubkey_serialize(ctx, out.data(), &size, &pubkey, SECP256K1_EC_COMPRESSED);
    secp256k1_context_destroy(ctx);
    return out;
}

inline std::array<uint8_t, 65> HDPrivate::privateToUncompressionPublic(std::array<uint8_t, 32> privateKey)
{

    //生成主公钥
    const auto ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey pubkey;
    const auto r = secp256k1_ec_pubkey_create(ctx, &pubkey, privateKey.data());
    if (r != 1)
    {
        return {};
    }

    std::array<uint8_t, 65> out;
    size_t size = out.size();
    secp256k1_ec_pubkey_serialize(ctx, out.data(), &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_context_destroy(ctx);
    return out;
}

std::array<uint8_t, 32> HDPrivate::privateKey()
{
    return privateKey_;
}

std::array<uint8_t, 33> HDPrivate::publicKey()
{
    return publicKey_;
}

std::array<uint8_t, 65> HDPrivate::uncompressionPublicKey()
{
    return privateToUncompressionPublic(privateKey_);
}

HDPrivate HDPrivate::derive(std::string path)
{

    std::vector<std::string> ret;
    std::string delim("/");
    split(path, delim, &ret);

    HDPrivate *parentHD = this;

    unsigned char depth = 0;
    for (int i = 0; i < ret.size(); i++)
    {

        std::string splitStr = ret.at(i);
        if (splitStr == "m")
        {
            continue;
        }

        bool isHardened = (ret.at(i).find("'") == std::string::npos ? false : true);
        if (isHardened)
        {

            //创建硬化密钥
            size_t quotesIndex = splitStr.find("'");
            int index = std::stoi(splitStr.replace(quotesIndex, 1, ""), nullptr, 10);
            std::vector<uint8_t> data_chunk = merge({0}, parentHD->privateKey_, to_big_endian((1 << 31) + index));
            std::array<uint8_t, 64> key = HMAC_SHA512(data_chunk, parentHD->chainCode_);

            std::array<uint8_t, 32> left;
            std::copy_n(std::begin(key), 32, left.begin());
            std::array<uint8_t, 32> right;
            std::copy_n(std::begin(key) + 32, 32, right.begin());

            std::array<uint8_t, 32> privateKey = parentHD->privateKey_;
            const auto ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
            int i = secp256k1_ec_privkey_tweak_add(ctx, privateKey.data(), left.data());
            secp256k1_context_destroy(ctx);

            HDPrivate privateHD = HDPrivate(privateKey, right, depth);
            parentHD = &privateHD;
        }
        else
        {

            //创建正常密钥
            int index = std::stoi(splitStr, nullptr, 10);
            std::vector<uint8_t> data_chunk = merge(parentHD->publicKey_, to_big_endian(index));
            std::array<uint8_t, 64> key = HMAC_SHA512(data_chunk, parentHD->chainCode_);

            std::array<uint8_t, 32> left;
            std::copy_n(std::begin(key), 32, left.begin());

            std::array<uint8_t, 32> right;
            std::copy_n(std::begin(key) + 32, 32, right.begin());

            std::array<uint8_t, 32> privateKey = parentHD->privateKey_;
            const auto ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
            int i = secp256k1_ec_privkey_tweak_add(ctx, privateKey.data(), left.data());
            secp256k1_context_destroy(ctx);

            HDPrivate privateHD = HDPrivate(privateKey, right, depth);
            parentHD = &privateHD;
        }
        depth++;
    }

    return *parentHD;
}
}
