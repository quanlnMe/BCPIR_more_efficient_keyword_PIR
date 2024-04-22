#ifndef SERVER_H
#define SERVER_H

#include "pir.h"
#include<vector>
#include<memory>
#include<map>

using namespace seal;
using namespace seal::util;
using namespace utils;

class PirServer
{
private:
    /* data */
    seal::EncryptionParameters enc_params;
    PirParams pir_params;
    std::unique_ptr<Database> db_;
    seal::GaloisKeys galoisKeys_;
    seal::GaloisKeys rotate_galois_;
    std::unique_ptr<seal::Evaluator> evaluator_;
    std::unique_ptr<seal::BatchEncoder> encoder_;
    std::shared_ptr<seal::SEALContext> context_;
    std::map<uint64_t, seal::Plaintext> map_;
    void multiply_power_of_X(const seal::Ciphertext &encrypted,seal::Ciphertext &destination,std::uint32_t index);
    seal::Ciphertext equality_operator(seal::Ciphertext &ct, std::uint32_t k);
    std::vector<seal::Plaintext> get_slot_pt();
    seal::RelinKeys relin_keys;

public:
    PirServer(const seal::EncryptionParameters &enc_params,const PirParams &pir_params);
    void set_database(std::unique_ptr<Database> &&db);
    void set_database(const std::unique_ptr<const uint8_t[]> &bytes, std::uint64_t ele_num, std::uint64_t ele_size);
    void process_database();
    std::vector<seal::Ciphertext> expand_query(const seal::Ciphertext &encrypted, std::uint32_t need_slot);
    void deserialize_relinkkeys(std::stringstream &stream);
    PirQuery deserialize_query(std::stringstream &stream);
    PirReply generate_reply(PirQuery query);
    int serialize_reply(PirReply &reply,std::stringstream &stream);
    void set_galoiskeys(seal::GaloisKeys galkey);
    void set_rotate_galois(seal::GaloisKeys galkey);
    //used to unique map from query field to vector<uint64_t>
    void single_map();

    
};

#endif