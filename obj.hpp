//
//  obj.hpp
//  defwallet
//
//  Created by 成岗 on 2018/4/4.
//

#ifndef obj_hpp
#define obj_hpp

#include <stdio.h>
#include <vector>

class obj
{
public:
    obj(const std::vector<uint8_t>& v);
    
    std::size_t size() const;
    
private:
    const size_t size_;
};

obj::obj(const std::vector<uint8_t>& v):size_(v.size()){
    
}

std::size_t obj::size() const {
    return size_;
}

#endif /* obj_hpp */
