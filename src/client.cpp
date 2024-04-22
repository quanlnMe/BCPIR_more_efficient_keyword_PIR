#include "client.h"
#define USED_SLOT 128
#define VALID_SLOT 124

PirClient::PirClient(const EncryptionParameters &enc_params,const PirParams &pir_params)
                    : enc_params(enc_params), pir_params(pir_params){
    context_ = make_shared<SEALContext>(enc_params, true);
    evaluator_ = make_unique<Evaluator>(*context_);
    encoder_ = make_unique<BatchEncoder>(*context_);
    keygen_ = make_unique<KeyGenerator>(*context_);
    PublicKey public_key;
    keygen_->create_public_key(public_key);
    SecretKey secret_key = keygen_->secret_key();
    encryptor_ = make_unique<Encryptor>(*context_,secret_key);
    decryptor_ = make_unique<Decryptor>(*context_,secret_key);
}

vector<uint64_t> PirClient::get_binary_string(uint64_t num){
    return constant_weight_map(num,VALID_SLOT,pir_params.k);
}

int PirClient::generate_serialized_query(std::uint64_t desire_field,std::stringstream &stream){
    vector<uint64_t> query = get_binary_string(desire_field);
    Plaintext query_(enc_params.poly_modulus_degree(),enc_params.poly_modulus_degree());
    for(uint64_t i = 0;i<query.size();i++)
    {
        if(query[i] == 1)
        {
            query_.data()[i] = invert_mod(USED_SLOT,enc_params.plain_modulus());
        }
    }
    int output_size = 0;
    output_size += encryptor_->encrypt_symmetric(query_).save(stream);
    return output_size;
}

PirQuery PirClient::generate_query(std::uint64_t desire_field){
    vector<uint64_t> query = get_binary_string(desire_field);
    cout<<"binary string generated"<<endl;
    Plaintext query_(enc_params.poly_modulus_degree(),enc_params.poly_modulus_degree());
    for(uint64_t i = 0;i<query.size();i++)
    {
        if(query[i] == 1)
        {
            query_.data()[i] = invert_mod(USED_SLOT,enc_params.plain_modulus());
        }
    }
    PirQuery query_ct;
    encryptor_->encrypt_symmetric(query_,query_ct);
    return query_ct;
    
}

seal::GaloisKeys PirClient::generate_rotate_galois(){
   // Generate the Galois keys needed for coeff_select.
  GaloisKeys gal_keys;
  keygen_->create_galois_keys(gal_keys);
  return gal_keys; 
}

seal::GaloisKeys PirClient::generate_galois_keys() {
  // Generate the Galois keys needed for coeff_select.
  vector<uint32_t> galois_elts;
  int N = enc_params.poly_modulus_degree();
  int logN = get_power_of_two(N);

  // cout << "printing galois elements...";
  for (int i = 0; i < logN; i++) {
    galois_elts.push_back((N + exponentiate_uint(2, i)) /
                          exponentiate_uint(2, i));
    //#ifdef DEBUG
    // cout << galois_elts.back() << ", ";
    //#endif
  }
  GaloisKeys gal_keys;
  keygen_->create_galois_keys(galois_elts, gal_keys);
  return gal_keys;
}

int PirClient::generate_serialized_relinkKey(std::stringstream &stream)
{
  int output_size = 0;
  RelinKeys relin_key;
  keygen_->create_relin_keys(relin_key);
  output_size += relin_key.save(stream);
  return output_size;
} 



vector<uint8_t> PirClient::decode_reply(PirReply &reply){
    Plaintext pt;
    vector<uint64_t> coeffs;
    vector<uint64_t> coeffs_valid;
    decryptor_->decrypt(reply,pt);
    encoder_->decode(pt,coeffs);
    int pointer = 0;
    if(coeffs[0]!=0) pointer += pir_params.ele_size / 2;//to find the first item
    for(int i = pointer;i<coeffs.size();i++)
    {
        if(coeffs[i]!=0)
        {
            coeffs_valid.push_back(coeffs[i]); //find the valid result
        }
    }
    vector<uint8_t> result_bytes(pir_params.ele_size);
    coeffs_to_bytes(coeffs_valid,coeffs_valid.size(),pir_params.ele_size/2,result_bytes.data());
    return result_bytes;
}