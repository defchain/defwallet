//
//  data_utils.cpp
//  DEFWalletSample
//
//  Created by 成岗 on 2018/4/20.
//  Copyright © 2018年 成岗. All rights reserved.
//

#include "data_utils.hpp"

std::vector<uint8_t> to_chunk(std::string str) {
    std::vector<uint8_t> chunk(std::begin(str),std::end(str));
    return chunk;
};

void split(std::string& s, std::string& delim,std::vector< std::string >* ret)
{
    size_t last = 0;
    size_t index=s.find_first_of(delim,last);
    while (index!=std::string::npos)
    {
        ret->push_back(s.substr(last,index-last));
        last=index+1;
        index=s.find_first_of(delim,last);
    }
    if (index-last>0)
    {
        ret->push_back(s.substr(last,index-last));
    }
}
