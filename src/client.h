#ifndef CLIENT_H
#define CLIENT_H

#include "pir.h"
#include<memory>
#include<vector>

using namespace seal;
using namespace seal::util;
using namespace utils;

class PirClient
{
private:
    /* data */
    seal::EncryptionParameters enc_params;
    PirParams pir_params;

    std::unique_ptr<seal::Encryptor> encryptor_;
    std::unique_ptr<seal::Decryptor> decryptor_;
    std::unique_ptr<seal::Evaluator> evaluator_;
    std::unique_ptr<seal::KeyGenerator> keygen_;
    std::unique_ptr<seal::BatchEncoder> encoder_;
    std::shared_ptr<seal::SEALContext> context_;
public:
    PirClient(const seal::EncryptionParameters &enc_params,const PirParams &pir_params);
    PirQuery generate_query(std::uint64_t desire_field);
    int generate_serialized_query(std::uint64_t desire_field,std::stringstream &stream);
    int generate_serialized_relinkKey(std::stringstream &stream);
    vector<uint8_t> decode_reply(PirReply &reply);
    std::vector<uint64_t> extract_coeffs(seal::Plaintext pt);

    seal::GaloisKeys generate_galois_keys();
    seal::GaloisKeys generate_rotate_galois();

    vector<uint64_t> get_binary_string(uint64_t num);    
};

#endif

