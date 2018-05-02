//
//  mnemonic.cpp
//  DEFWalletSample
//
//  Created by 成岗 on 2018/4/19.
//  Copyright © 2018年 成岗. All rights reserved.
//

#include "mnemonic.hpp"
#include <iostream>
#include "assert.h"
#include "../crypto/sha256.h"
#include "../crypto/pkcs5_pbkdf2.h"

namespace libdefwallet
{
    
    const uint8_t byte_bits = 8;
    static const size_t entropy_bit_divisor = 32;
    static const size_t bits_per_word = 11;
    
    typedef std::vector<std::string> string_list;
    typedef string_list word_list;
    
    inline std::vector<uint8_t> build_chunk(std::vector<uint8_t> entropy){
        
        uint8_t digest[SHA256_DIGEST_LENGTH];
        SHA256_(entropy.data(),entropy.size(),digest);
        for (int i = 0 ;i < sizeof(digest); i ++) {
            entropy.insert(entropy.end(), digest[i]);
        }
        return entropy;
    }
    
    inline uint8_t bip39_shift(size_t bit)
    {
        return (1 << (byte_bits - (bit % byte_bits) - 1));
    }
    
    std::vector<std::string> mnemonic::create_mnemonic(std::vector<uint8_t> entropy,const dictionary &lexicon) {
        if ((entropy.size() % mnemonic_seed_multiple) != 0)
            return {};
        
        const size_t entropy_bits = (entropy.size() * byte_bits);
        const size_t check_bits = (entropy_bits / entropy_bit_divisor);
        const size_t total_bits = (entropy_bits + check_bits);
        const size_t word_count = (total_bits / bits_per_word);
        
        assert((total_bits % bits_per_word) == 0);
        assert((word_count % mnemonic_word_multiple) == 0);
        
        const auto data = build_chunk(entropy);
        
        size_t bit = 0;
        word_list words;
        
        for (size_t word = 0; word < word_count; word++)
        {
            size_t position = 0;
            for (size_t loop = 0; loop < bits_per_word; loop++)
            {
                bit = (word * bits_per_word + loop);
                position <<= 1;
                
                const auto byte = bit / byte_bits;
                
                if ((data[byte] & bip39_shift(bit)) > 0)
                    position++;
            }
            
            assert(position < dictionary_size);
            words.push_back(lexicon[position]);
        }
        
        return words;
    }
    
    bool mnemonic::validate_mnemonic(const std::vector<std::string>& words,const dictionary& lexicon) {
        
        const auto word_count = words.size();
        if ((word_count % mnemonic_word_multiple) != 0)
            return false;
        
        const auto total_bits = bits_per_word * word_count;
        const auto check_bits = total_bits / (entropy_bit_divisor + 1);
        const auto entropy_bits = total_bits - check_bits;
        
        assert((entropy_bits % byte_bits) == 0);
        
        size_t bit = 0;
        std::vector<uint8_t> data((total_bits + byte_bits - 1) / byte_bits, 0);
        
        for (const auto& word: words)
        {
            int position = 0;
            const auto& it = std::find(std::begin(lexicon), std::end(lexicon), word);
            if(it == std::end(lexicon)){
                position = -1;
            }
            position = static_cast<int>(std::distance(lexicon.begin(), it));
            
            if (position == -1)
                return false;
            
            for (size_t loop = 0; loop < bits_per_word; loop++, bit++)
            {
                if (position & (1 << (bits_per_word - loop - 1)))
                {
                    const auto byte = bit / byte_bits;
                    data[byte] |= bip39_shift(bit);
                }
            }
        }
        
        data.resize(entropy_bits / byte_bits);
        const auto mnemonic = mnemonic::create_mnemonic(data, lexicon);
        return std::equal(mnemonic.begin(), mnemonic.end(), words.begin());
    }
    
    std::array<uint8_t, 64> mnemonic::decode_mnemonic(const std::vector<std::string>& words) {
        
        std::string sentence = "";
        for(int i = 0;i < words.size();i ++){
            sentence += words.at(i);
            if(i != words.size() - 1)
                sentence += " ";
        }
        std::vector<uint8_t> sentence_chunk(std::begin(sentence),std::end(sentence));
        
        const std::string salt("mnemonic");
        std::vector<uint8_t> salt_chunk(std::begin(salt),std::end(salt));
        std::array<uint8_t, 64> hash;
        pkcs5_pbkdf2(sentence_chunk.data(), sentence_chunk.size(),salt_chunk.data(), salt_chunk.size(), hash.data(), hash.size(), 2048);
        return hash;
    }
}
