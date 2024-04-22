#ifndef PIR_H
#define PIR_H

#include "seal/seal.h"
#include "seal/util/polyarithsmallmod.h"
#include<string>
#include<vector>
#include<iostream>
#include "utils.h"

using namespace std;

typedef std::vector<seal::Plaintext> Database;
typedef seal::Ciphertext PirQuery;
typedef seal::Ciphertext PirReply;

struct PirParams {
    std::uint64_t ele_num;
    std::uint64_t ele_size;
    std::uint64_t k; //  constant-hamming-code k
    std::uint64_t m;
    std::uint64_t block_num;
    std::uint64_t num_plaintexts;
    //std::uint64_t h; //the num of ciphertext to store database
};

void gen_encrypt_params(std::uint32_t N, std::uint32_t logt, seal::EncryptionParameters &enc_params);
void gen_pir_params(uint64_t ele_num,uint64_t ele_size,PirParams &pirparams);

std::uint64_t byte_num_per_coefficient(std::uint32_t logt);

//put two bytes into one uint64_t,and form coefficients
std::uint64_t bytes_to_coeffs(uint32_t limit,const std::uint8_t *bytes,std::uint64_t size);

void coeffs_to_bytes(std::vector<uint64_t> coeffs,std::uint64_t size,std::uint64_t ele_size,std::uint8_t *output);

std::string serialize_galoiskeys(seal::Serializable<seal::GaloisKeys> g);

seal::GaloisKeys * deserialize_galoiskeys(std::string s, std::shared_ptr<seal::SEALContext> context);

std::uint64_t invert_mod(uint64_t m,const seal::Modulus &mod);

#endif