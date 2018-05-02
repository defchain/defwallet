//
//  main.cpp
//  DEFWalletSample
//
//  Created by 成岗 on 2018/4/19.
//  Copyright © 2018年 成岗. All rights reserved.
//

#include <iostream>
#include <vector>
#include <string>
#include "libDEFWallet/mnemonic/mnemonic.hpp"
#include "libDEFWallet/hd/hd_private.hpp"
#include "libDEFWallet/crypto/sha3.h"

template <class Iterator>
std::string toHex(Iterator _it, Iterator _end, std::string const& _prefix)
{
    typedef std::iterator_traits<Iterator> traits;
    static_assert(sizeof(typename traits::value_type) == 1, "toHex needs byte-sized element type");
    
    static char const* hexdigits = "0123456789abcdef";
    size_t off = _prefix.size();
    std::string hex(std::distance(_it, _end)*2 + off, '0');
    hex.replace(0, off, _prefix);
    for (; _it != _end; _it++)
    {
        hex[off++] = hexdigits[(*_it >> 4) & 0x0f];
        hex[off++] = hexdigits[*_it & 0x0f];
    }
    return hex;
}

/// Convert the given value into h160 (160-bit unsigned integer) using the right 20 bytes.
inline std::array<uint8_t, 20>  right160(std::array<uint8_t, 32> const& _t)
{
    std::array<uint8_t, 20> ret;
    memcpy(ret.data(), _t.data() + 12, 20);
    return ret;
}

/// Convert the given value into h160 (160-bit unsigned integer) using the right 20 bytes.
inline std::vector<uint8_t> right160(std::vector<uint8_t> const& _t)
{
    std::vector<uint8_t> ret(20);
    memcpy(ret.data(), _t.data() + 12, 20);
    return ret;
}

int main(int argc, const char * argv[]) {
    
    std::vector<uint8_t> entropy = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    std::vector<std::string> words = libdefwallet::mnemonic::create_mnemonic(entropy);
    std::cout << "助记词:";
    for(int i = 0 ; i < words.size();i ++) {
        std::cout << words.at(i) << " ";
    }
    std::cout << std::endl;
    
    bool isValidate = libdefwallet::mnemonic::validate_mnemonic(words);
    if(isValidate){
        std::cout << "验证通过" << std::endl;
    }
    
    std::array<uint8_t, 64> seeds = libdefwallet::mnemonic::decode_mnemonic(words);
    std::cout << "生成 seeds:" << toHex(seeds.begin(), seeds.end(), "0x") << std::endl;
    
    libdefwallet::HDPrivate masterKey = libdefwallet::HDPrivate(seeds,0x0488ADE4);
    libdefwallet::HDPrivate theKey = masterKey.derive("m/44'/60'/0'/0/0");
    std::array<uint8_t, 32> priKey = theKey.privateKey();
    std::cout << "生成m/44'/60'/0'/0/0 密钥:" << toHex(priKey.begin(), priKey.end(), "0x") << std::endl;
    
    std::array<uint8_t, 33> publicKey = theKey.publicKey();
    std::cout << "生成m/44'/60'/0'/0/0 压缩公钥:" << toHex(publicKey.begin(), publicKey.end(), "") << std::endl;
    
    std::array<uint8_t, 65> uncompressionPublicKey = theKey.uncompressionPublicKey();
    std::cout << "生成m/44'/60'/0'/0/0 未压缩公钥:" << toHex(uncompressionPublicKey.begin(), uncompressionPublicKey.end(), "") << std::endl;
    
    std::array<uint8_t, 64> thePublicKey;
    std::copy_n(std::begin(uncompressionPublicKey) + 1, 64 , thePublicKey.begin());
    std::array<uint8_t, 32> address;
    ethsha3(thePublicKey, address);
    std::array<uint8_t, 20> add = right160(address);
    std::cout << "生成m/44'/60'/0'/0/0 地址:0x" << toHex(add.begin(), add.end(), "") << std::endl;
    
    return 0;
}
