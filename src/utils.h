#ifndef UTILS_H
#define UTILS_H

#include <vector>
#include <cmath>
#include <iostream>
#include <cstdint>
#include <memory>
#include "seal/seal.h"

using namespace std;
using namespace seal;

namespace utils {
    inline std::size_t get_capacity(uint64_t m, uint64_t k)
    {
        size_t block_num = floor(m / k);
        size_t result = 1;
        while (k--)
        {
            /* code */
            result *= block_num;   
        }
        return result;
    }
    inline std::size_t hash_mod(std::uint64_t num)
    {
        std:;hash<std::string> hasher1;
        size_t num1 = num /100;
        size_t num2 = num % 100;
        return hasher1(std::to_string(num1) + std::to_string(num2)) % 1000000;
    }

    inline uint64_t choose(uint64_t n, uint64_t k) {
    if (k > n) {
        return 0;
    }
    uint64_t r = 1;
    for (uint64_t d = 1; d <= k; ++d) {
        r *= n--;
        r /= d;
    }
    return r;
}

    inline vector<uint64_t> constant_weight_map(uint64_t num, uint64_t m, uint64_t hamming_weight)
    {
        vector<uint64_t> weight_map(m, 0);
        size_t block_num = floor(m/hamming_weight);
        uint64_t k_prime = hamming_weight;
        size_t capacity = get_capacity(m, hamming_weight);
        while(num>capacity)
        {
            num -= capacity;
        }
        int index = 0;
        size_t copy_capacity = capacity;
       
            for(int j = 0;j<hamming_weight;j++)
            {
                copy_capacity /= block_num;
                index = num / copy_capacity;
                num = num - index * copy_capacity;
                weight_map[index + j * block_num] = 1;

            }
        return weight_map;
    }
    inline void multiply_acum(uint64_t op1, uint64_t op2, __uint128_t& product_acum)
    {
        product_acum = product_acum + static_cast<__uint128_t>(op1) * static_cast<__uint128_t>(op2); 
    }

    inline void multiply_poly_acum(const uint64_t *ct_ptr, const uint64_t *pt_ptr,size_t size,uint128_t *result)
    {

    }
 
}  //namespace utils

#endif