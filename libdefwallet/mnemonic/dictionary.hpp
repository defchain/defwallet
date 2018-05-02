
#ifndef LIB_DEF_WALLET_DICTIONSRY_H
#define LIB_DEF_WALLET_DICTIONSRY_H

#include <cstddef>
#include <array>
#include <vector>

namespace libdefwallet {


static const size_t dictionary_size = 2048;

typedef std::array<const char*, dictionary_size> dictionary;

typedef std::vector<const dictionary*> dictionary_list;

namespace language {

extern const dictionary en;
extern const dictionary es;
extern const dictionary ja;
extern const dictionary it;
extern const dictionary fr;
extern const dictionary cs;
extern const dictionary ru;
extern const dictionary uk;
extern const dictionary zh_Hans;
extern const dictionary zh_Hant;

// All built-in languages:
extern const dictionary_list all;

} // namespace language

} // namespace wallet

#endif
