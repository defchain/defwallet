//
//  main.cpp
//  defwallet
//
//  Created by 成岗 on 2018/4/4.
//

#include <iostream>
#include "libdefwallet/mnemonic/mnemonic.hpp"
#include "libdefwallet/mnemonic/dictionary.hpp"
#include "libdefwallet/crypto/hmac_sha512.h"
#include "lib/secp256k1.h"

using namespace std;

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

/**
 *  私钥生成公钥
 **/
array<uint8_t, 33> privateToPublic(array<uint8_t, 32> privateKey) {
    
    //生成主公钥
    const auto ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey pubkey;
    const auto r = secp256k1_ec_pubkey_create(ctx, &pubkey, privateKey.data());
    
    std::array<uint8_t, 33> out;
    size_t size = out.size();
    secp256k1_ec_pubkey_serialize(ctx, out.data(), &size, &pubkey, SECP256K1_EC_COMPRESSED);
    secp256k1_context_destroy(ctx);
    return out;
}

vector<uint8_t> merge(array<uint8_t, 33> a,array<uint8_t, 4> b) {
    vector<uint8_t> out;
    out.reserve(37);
    out.insert(out.end(),a.begin(),a.end());
    out.insert(out.end(), b.begin(),b.end());
    return out;
}

vector<uint8_t> merge(array<uint8_t, 1> a,array<uint8_t, 32> b,array<uint8_t, 4> c) {
    vector<uint8_t> out;
    out.reserve(37);
    out.insert(out.end(),a.begin(),a.end());
    out.insert(out.end(), b.begin(),b.end());
    out.insert(out.end(), c.begin(),c.end());
    return out;
}

array<uint8_t, 64> HMAC_SHA512(vector<uint8_t> data,array<uint8_t, 32> key) {
    
    array<uint8_t, 64> out;
    HMACSHA512(data.data(), data.size(), key.data(), key.size(), out.data());
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

int main(int argc, const char * argv[]) {
    
//    uint32_t aa = 0;
//    const auto list = to_big_endian(aa);
//    for(int i = 0 ;i < list.size();i ++){
//        cout << (int)list.at(i) << endl;
//    }
    
    //创建助记词
    vector<uint8_t> a = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    vector<string> words =  libdefwallet::create_mnemonic(a);
    cout << "生成助记词:";
    for (int i = 0 ;i < words.size();i ++) {
        cout << words.at(i) << " ";
    }
    cout << endl;
    
    //验证助记词
//    vector<string> words = {"abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "about"};
//    bool isValidate = libdefwallet::validate_mnemonic(words);
//    if(isValidate)
//        cout << "验证通过";
    
    //生成seeds
    array<uint8_t, 64> seeds = libdefwallet::decode_mnemonic(words);
    string str = toHex(seeds.begin(), seeds.end(), "0x");
    cout << "生成seeds:" << str << endl;
    
    //创建主密钥
    const std::string key("Bitcoin seed");
    std::vector<uint8_t> key_chunk(std::begin(key),std::end(key));
    std::array<uint8_t, 64> masterKey;
    HMACSHA512(seeds.data(), seeds.size(), key_chunk.data(), key_chunk.size(), masterKey.data());
    str = toHex(masterKey.begin(), masterKey.end(), "0x");
    cout << "生成主密钥:" << str <<endl;
    
    //截取主私钥&主链码
    std::array<uint8_t, 32> masterPrivateKey;
    std::array<uint8_t, 32> masterChainKey;
    std::copy_n(std::begin(masterKey), 32 , masterPrivateKey.begin());
    std::copy_n(std::begin(masterKey) + 32,32,masterChainKey.begin());
    str = toHex(masterPrivateKey.begin(), masterPrivateKey.end(), "0x");
    cout << "生成主私钥:" << str <<endl;
    str = toHex(masterChainKey.begin(), masterChainKey.end(), "0x");
    cout << "生成主链码:" << str <<endl;

    //生成主公钥
    std::array<uint8_t, 33> masterPublicKey = privateToPublic(masterPrivateKey);
    str = toHex(masterPublicKey.begin(), masterPublicKey.end(), "");
    cout << "生成主公钥:" << str << endl;

    //m/0
//    vector<uint8_t> data_chunk = merge(masterPublicKey,to_big_endian(0));
//    array<uint8_t,64> oKey = HMAC_SHA512(data_chunk,masterChainKey);
//    str = toHex(oKey.begin(), oKey.end(), "0x");
//    cout << "生成m/0密钥:" << str << endl;
//
//    std::array<uint8_t, 32> left;
//    std::copy_n(std::begin(oKey), 32 , left.begin());
//    str = toHex(left.begin(), left.end(), "0x");
//    cout << "left:" << str <<endl;
//
//    std::array<uint8_t, 32> child;
//    std::copy_n(std::begin(masterPrivateKey), 32 , child.begin());
//    str = toHex(child.begin(), child.end(), "0x");
//    cout << "child:" << str <<endl;
//
//    const auto ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
//    int i = secp256k1_ec_privkey_tweak_add(ctx, child.data(),left.data());
//    cout << i << endl;
//
//    str = toHex(child.begin(), child.end(), "0x");
//    cout << "m/0 private key:" << str <<endl;
//
//    array<uint8_t, 33> m0PublicKey = privateToPublic(child);
//    str = toHex(m0PublicKey.begin(), m0PublicKey.end(), "0x");
//    cout << "m/0 public key:" << str <<endl;
    
    //m/44'
    std::array<uint8_t, 1> depth{{0}};
    vector<uint8_t> data_chunk = merge(depth,masterPrivateKey,to_big_endian((1 << 31) + 44));
    array<uint8_t,64> m44Key = HMAC_SHA512(data_chunk,masterChainKey);
    str = toHex(m44Key.begin(), m44Key.end(), "0x");
    cout << "m44Key:" << str <<endl;
    
    std::array<uint8_t, 32> left;
    std::copy_n(std::begin(m44Key), 32 , left.begin());
    str = toHex(left.begin(), left.end(), "0x");
    cout << "left:" << str <<endl;
    
    std::array<uint8_t, 32> right;
    std::copy_n(std::begin(m44Key) + 32, 32 , right.begin());
    str = toHex(right.begin(), right.end(), "0x");
    cout << "right:" << str <<endl;
    
    std::array<uint8_t, 32> child;
    std::copy_n(std::begin(masterPrivateKey), 32 , child.begin());
    str = toHex(child.begin(), child.end(), "0x");
    cout << "child:" << str <<endl;
    
    const auto ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    int i = secp256k1_ec_privkey_tweak_add(ctx, child.data(),left.data());
    cout << i << endl;
    secp256k1_context_destroy(ctx);
    
    str = toHex(child.begin(), child.end(), "0x");
    cout << "m/44' private key:" << str <<endl;
    
    std::array<uint8_t, 33> m44PublicKey = privateToPublic(child);
    str = toHex(m44PublicKey.begin(), m44PublicKey.end(), "0x");
    cout << "m/44' public key:" << str <<endl;
    
    //m/44'/0
    vector<uint8_t> dk = merge(m44PublicKey,to_big_endian(0));
    array<uint8_t,64> ffoKey = HMAC_SHA512(dk,right);
    str = toHex(ffoKey.begin(), ffoKey.end(), "0x");
    cout << "生成m/44'/0密钥:" << str << endl;

    std::copy_n(std::begin(ffoKey), 32 , left.begin());
    str = toHex(left.begin(), left.end(), "0x");
    cout << "left:" << str <<endl;

    str = toHex(child.begin(), child.end(), "0x");
    cout << "child:" << str <<endl;

    const auto c = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    i = secp256k1_ec_privkey_tweak_add(c, child.data(),left.data());
    cout << i << endl;

    str = toHex(child.begin(), child.end(), "0x");
    cout << "m/44'/0 private key:" << str <<endl;
    
    return 0;
}
