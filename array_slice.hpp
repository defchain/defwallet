//
//  array_slice.hpp
//  defwallet
//
//  Created by 成岗 on 2018/4/4.
//

#ifndef array_slice_hpp
#define array_slice_hpp

#include <stdio.h>
#include <cstddef>

template <typename Iterable>
class array_slice
{
public:
    
    template <typename Container>
    array_slice(const Container& container);
    
    array_slice(const Iterable* begin, const Iterable* end);
    
    const Iterable* begin() const;
    const Iterable* end() const;
    const Iterable* data() const;
    std::size_t size() const;
    bool empty() const;
    
private:
    const Iterable* begin_;
    const Iterable* end_;
};

template <typename Iterable>
template <typename Container>
array_slice<Iterable>::array_slice(const Container& container)
: begin_(container.data()), end_(container.data() + container.size())
{
}

template <typename Iterable>
array_slice<Iterable>::array_slice(const Iterable* begin, const Iterable* end)
: begin_(begin), end_(end)
{
}

template <typename Iterable>
const Iterable* array_slice<Iterable>::begin() const
{
    return begin_;
}

template <typename Iterable>
const Iterable* array_slice<Iterable>::end() const
{
    return end_;
}

template <typename Iterable>
const Iterable* array_slice<Iterable>::data() const
{
    return begin_;
}

template <typename Iterable>
std::size_t array_slice<Iterable>::size() const
{
    return end_ - begin_;
}

template <typename Iterable>
bool array_slice<Iterable>::empty() const
{
    return end_ == begin_;
}

#endif /* array_slice_hpp */
