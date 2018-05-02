//
//  data_utils.hpp
//  DEFWalletSample
//
//  Created by 成岗 on 2018/4/20.
//  Copyright © 2018年 成岗. All rights reserved.
//

#ifndef data_utils_hpp
#define data_utils_hpp

#include <stdio.h>
#include <vector>
#include <string>

std::vector<uint8_t> to_chunk(std::string str);

void split(std::string& s, std::string& delim,std::vector< std::string >* ret);

#endif /* data_utils_hpp */
