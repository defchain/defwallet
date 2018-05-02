//
//  mnemonic.hpp
//  DEFWalletSample
//
//  Created by 成岗 on 2018/4/19.
//  Copyright © 2018年 成岗. All rights reserved.
//

#ifndef mnemonic_hpp
#define mnemonic_hpp

#include <stdio.h>
#include <string>
#include <vector>
#include "dictionary.hpp"

namespace libdefwallet {
    
    static const size_t mnemonic_word_multiple = 3;
    static const size_t mnemonic_seed_multiple = 4;
    
    class mnemonic
    {
    public:
        
        static std::vector<std::string> create_mnemonic(std::vector<uint8_t> entropy,const dictionary &lexicon=language::en);
        
        static bool validate_mnemonic(const std::vector<std::string>& words,const dictionary& lexicon=language::en);
        
        static std::array<uint8_t, 64> decode_mnemonic(const std::vector<std::string>& words);
    };
    
}

#endif /* mnemonic_hpp */
