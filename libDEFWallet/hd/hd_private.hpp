//
//  hd_private.hpp
//  DEFWalletSample
//
//  Created by 成岗 on 2018/4/20.
//  Copyright © 2018年 成岗. All rights reserved.
//

#ifndef hd_private_hpp
#define hd_private_hpp

#include <stdio.h>
#include <array>

namespace libdefwallet {
 
    class HDPrivate
    {
        
    public:
        
        HDPrivate(std::array<uint8_t,64>& seeds,uint64_t prefixes);
        HDPrivate(std::array<uint8_t, 32> privateKey,std::array<uint8_t, 32> chainCode,unsigned char depth);
        HDPrivate derive(std::string path);
        
        std::array<uint8_t, 32> privateKey();
        std::array<uint8_t, 33> publicKey();
        std::array<uint8_t, 65> uncompressionPublicKey();
        
    private:
        
        std::array<uint8_t, 32> privateKey_;
        std::array<uint8_t, 33> publicKey_;
        std::array<uint8_t, 32> chainCode_;
        std::array<uint8_t, 33> privateToPublic(std::array<uint8_t, 32> privateKey);
        std::array<uint8_t, 65> privateToUncompressionPublic(std::array<uint8_t, 32> privateKey);
        
        int depth_;
    };
    
}

#endif /* hd_private_hpp */
