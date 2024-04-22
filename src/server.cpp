#include "server.h"
#define USED_SLOT 128
#define VALID_SLOT 124


PirServer::PirServer(const EncryptionParameters &enc_params,
                     const PirParams &pir_params)
    : enc_params(enc_params), pir_params(pir_params) {
  context_ = make_shared<SEALContext>(enc_params, true);
  evaluator_ = make_unique<Evaluator>(*context_);
  encoder_ = make_unique<BatchEncoder>(*context_);
  single_map();
}

void PirServer::set_database(std::unique_ptr<Database> &&db) {
  db_ = move(db);
}


void PirServer::set_database(const std::unique_ptr<const uint8_t[]> &bytes, std::uint64_t ele_num, std::uint64_t ele_size) {
    uint32_t logt = floor(log2(enc_params.plain_modulus().value()));
    uint32_t N = enc_params.poly_modulus_degree();
    auto result = make_unique<vector<Plaintext>>();
    int num_plaintext = ele_num / N * ele_size / 2;
    vector<vector<uint64_t>> coefficients = vector<vector<uint64_t>>(num_plaintext, vector<uint64_t>(N,0));//just see one coefficient contain two bytes
    cout<<"Elements num is "<<ele_num<<endl;
    int offset = 0;
    //guarantee the minum size of plaintext
    for(uint64_t j = 0;j< 2 * num_plaintext/ele_size;j++){ //which slot  column
            for(uint64_t i = 0;i< N;i++)  //which slot row
            { 
                for(uint64_t k = 0;k<ele_size/2;k++)
                {   
                    uint64_t coeff = bytes_to_coeffs(logt,bytes.get()+offset,2);
                    offset += 2;
                    coefficients[k + j* ele_size/2][i] = coeff;
                }
                
            }
    }
    cout<<"database palintexts size is "<<coefficients.size()<<endl;
   //now we can encode these coefficients into plaintexts
    for(uint64_t i = 0;i< coefficients.size();i++)
    {
        Plaintext p;
        encoder_->encode(coefficients[i], p);
        result->push_back(move(p));
    }
    //db_ = make_unique<Database>(std::move(result));
    set_database(std::move(result));
}


void PirServer::process_database() {
    
}
void PirServer::single_map()
{
    /* this i represent the data-item,for example , data-item  contains four bytes,
      the field is two bytes,and every bytes is from 00 - 20,so we can represent the two bytes as first byte * 100 and last byte *1,
      and the range is from 0000(0) ~ 2020*/
      cout<<"Map the keywords"<<endl;
    uint64_t N = enc_params.poly_modulus_degree();
    vector<vector<uint64_t>> coeffcients;
    for(uint64_t i = 0;i<=pir_params.ele_num;i++)
    {
        /* generate the unique constant weight map
         and we can map the dataitem to only one codeword 
        */
        vector<uint64_t> coeff = constant_weight_map(i,VALID_SLOT,pir_params.k);
        // for(int j = 0;j<coeff.size();j++)
        // {
        //     cout<<coeff[j]<<" ";
        // }
        // cout<<endl;
        coeffcients.push_back(coeff);
    }
    uint64_t column = pir_params.ele_num / N;
    vector<vector<uint64_t>> result= vector<vector<uint64_t>>(column * VALID_SLOT, vector<uint64_t>(N,0));
    for(int i = 0;i<column;i++)
    {
        for(int j = 0;j<N;j++)
        {
            for(int k = 0;k<VALID_SLOT;k++){
                result[i * VALID_SLOT + k][j] = coeffcients[j + i*N][k];
            }
        }
    }
    for(uint64_t i = 0;i<result.size();i++)
    {
        result[i][N-1] = 1;
        Plaintext pt;
        encoder_->encode(result[i],pt);
        map_[i] = move(pt);
    }
    
}

int PirServer::serialize_reply(PirReply &reply,std::stringstream &stream)
{
    int output_size = 0;
    evaluator_->mod_switch_to_inplace(reply,context_->last_parms_id());
    output_size += reply.save(stream);
    return output_size;
}
PirReply PirServer::generate_reply(PirQuery query){
    uint64_t N = enc_params.poly_modulus_degree();
    vector<Plaintext> *cur = db_.get();
    vector<Ciphertext> expanded_query = expand_query(query,USED_SLOT);
    cout<<"Server : expanded over"<<endl;
    int column = (*cur).size()/(pir_params.ele_size/2);
    cout<<"Server: expanded query multiply the keyword"<<endl;
    vector<Ciphertext> keyword_ciphertexts;
    for(int j = 0;j<column;j++){
        for(int i = 0;i<VALID_SLOT;i++)
        {
            Ciphertext tag ;
            evaluator_->multiply_plain(expanded_query[i],map_[i + j * VALID_SLOT],tag);
            keyword_ciphertexts.push_back(tag);
        }
    }
    //add the keyword slot based on block encoding
    cout<<"Server : add the keyword slot based on block encoding"<<endl;
    vector<vector<Ciphertext>> inter;
    
    for(int k = 0;k< column;k++){
        vector<Ciphertext> inter_cipher;
        for(int i = 0;i<pir_params.k;i++)
        {
            Ciphertext temp = keyword_ciphertexts[i*pir_params.block_num + k * pir_params.m]; //pir_params.m is the keyword ciphertext in every column
            for (int j = 1; j < pir_params.block_num; j++)
            {
                /* code */
                evaluator_->add_inplace(temp,keyword_ciphertexts[i * pir_params.block_num + j + k * pir_params.m]);
                
            }
            inter_cipher.push_back(temp);
        }
        inter.push_back(inter_cipher);
    }
    Ciphertext result;
    
    cout<<"Server: start find the desire slot in keyword codeword"<<endl;
    vector<vector<Ciphertext>> result_db;
    for(int i = 0;i<column;i++)
    {
        vector<Ciphertext> temp_db;
        evaluator_->multiply_many(inter[i],relin_keys,result);
        cout<<"multiply many over"<<endl;
        for(int j = 0;j<pir_params.ele_size/2;j++)
        {
            Ciphertext vec_result;
            evaluator_->multiply_plain(result,(*cur)[i*pir_params.ele_size/2 + j],vec_result); //multiply the database
            temp_db.push_back(vec_result);
        }
        result_db.push_back(temp_db);
    }
    vector<uint64_t> vec(N,1);
    vec[N-1] = 0;
    Plaintext pt ;
    encoder_->encode(vec,pt);
    //database entry add 
    for(int i = 0;i<result_db[0].size();i++)
    {
        for(int j = 1;j<column;j++)
        {
            evaluator_->add_inplace(result_db[0][i],result_db[j][i]);
        }
        evaluator_->multiply_plain_inplace(result_db[0][i],pt);
    }
    for(int i = 0;i<result_db[0].size();i++)
    {
        //cout<<"rotate and add"<<endl;
        evaluator_->rotate_rows_inplace(result_db[0][i],i,rotate_galois_);
    }
    Ciphertext result_in_all = result_db[0][0];
    for(int i = 1;i<result_db[0].size();i++)
    {
        evaluator_->add_inplace(result_in_all,result_db[0][i]);
    }
    return result_in_all;
    
}


inline vector<Ciphertext> PirServer::expand_query(const Ciphertext &encrypted,uint32_t need_slot)
{
    GaloisKeys &galkey = galoisKeys_;

    // Assume that m is a power of 2. If not, round it to the next power of 2.
    uint32_t logm = ceil(log2(need_slot));
    Plaintext two("2");

    vector<int> galois_elts;
    auto n = enc_params.poly_modulus_degree();
    if (logm > ceil(log2(n))) {
        throw logic_error("m > n is not allowed.");
    }
    for (int i = 0; i < ceil(log2(n)); i++) {
        galois_elts.push_back((n + exponentiate_uint(2, i)) /
                            exponentiate_uint(2, i));
    }

    vector<Ciphertext> temp;
    temp.push_back(encrypted);
    Ciphertext tempctxt;
    //rotated / shifted /rotatedshifted ???
    Ciphertext tempctxt_rotated;
    Ciphertext tempctxt_shifted;
    Ciphertext tempctxt_rotatedshifted;
    //section 3.3 in Sealpir's paper,figure 3
    for (uint32_t i = 0; i < logm - 1; i++) {
        vector<Ciphertext> newtemp(temp.size() << 1);
        // temp[a] = (j0 = a (mod 2**i) ? ) : Enc(x^{j0 - a}) else Enc(0).  With
        // some scaling....
        int index_raw = (n << 1) - (1 << i);
        int index = (index_raw * galois_elts[i]) % (n << 1);

        for (uint32_t a = 0; a < temp.size(); a++) {

        evaluator_->apply_galois(temp[a], galois_elts[i], galkey,
                                tempctxt_rotated);

        // cout << "rotate " <<
        // client.decryptor_->invariant_noise_budget(tempctxt_rotated) << ", ";

        evaluator_->add(temp[a], tempctxt_rotated, newtemp[a]);
        multiply_power_of_X(temp[a], tempctxt_shifted, index_raw);

        // cout << "mul by x^pow: " <<
        // client.decryptor_->invariant_noise_budget(tempctxt_shifted) << ", ";
        
        multiply_power_of_X(tempctxt_rotated, tempctxt_rotatedshifted, index);

        // cout << "mul by x^pow: " <<
        // client.decryptor_->invariant_noise_budget(tempctxt_rotatedshifted) <<
        // ", ";

        // Enc(2^i x^j) if j = 0 (mod 2**i).
        evaluator_->add(tempctxt_shifted, tempctxt_rotatedshifted,
                        newtemp[a + temp.size()]);
        }
        temp = newtemp;
        /*
        cout << "end: ";
        for (int h = 0; h < temp.size();h++){
            cout << client.decryptor_->invariant_noise_budget(temp[h]) << ", ";
        }
        cout << endl;
        */
    }
    // Last step of the loop
    vector<Ciphertext> newtemp(temp.size() << 1);
    int index_raw = (n << 1) - (1 << (logm - 1));
    int index = (index_raw * galois_elts[logm - 1]) % (n << 1);
    for (uint32_t a = 0; a < temp.size(); a++) {
        if (a >= (need_slot - (1 << (logm - 1)))) { // corner case.
        evaluator_->multiply_plain(temp[a], two,
                                    newtemp[a]); // plain multiplication by 2.
        // cout << client.decryptor_->invariant_noise_budget(newtemp[a]) << ", ";
        } else {
        evaluator_->apply_galois(temp[a], galois_elts[logm - 1], galkey,
                                tempctxt_rotated);
        evaluator_->add(temp[a], tempctxt_rotated, newtemp[a]);
        multiply_power_of_X(temp[a], tempctxt_shifted, index_raw);
        multiply_power_of_X(tempctxt_rotated, tempctxt_rotatedshifted, index);
        evaluator_->add(tempctxt_shifted, tempctxt_rotatedshifted,
                        newtemp[a + temp.size()]);
        }
    }

    vector<Ciphertext>::const_iterator first = newtemp.begin();
    vector<Ciphertext>::const_iterator last = newtemp.begin() + need_slot;
    vector<Ciphertext> newVec(first, last);

    return newVec;
}

PirQuery PirServer::deserialize_query(stringstream &stream)
{
  PirQuery q;
  /*
  uint32_t ctx = ceil((pir_params_.num_ofPlaintexts + 0.0)/enc_params_.poly_modulus_degree());
  vector<Ciphertext> cs;
  for(uint32_t i=0; i<ctx; i++)
  {
    Ciphertext c;
    c.load(*context_,stream);
    cs.push_back(c);
  }
  q = cs;
  */
  Ciphertext c ;
  c.load(*context_,stream);
  q=c;
  return q;
}

void PirServer::deserialize_relinkkeys(stringstream &stream)
{
  this->relin_keys.load(*context_,stream);
}

inline void PirServer::multiply_power_of_X(const Ciphertext &encrypted, Ciphertext &destination, uint32_t index){
    auto coeff_mod_count = enc_params.coeff_modulus().size() - 1;
    auto coeff_count = enc_params.poly_modulus_degree();
    auto encrypted_count = encrypted.size();

    // cout << "coeff mod count for power of X = " << coeff_mod_count << endl;
    // cout << "coeff count for power of X = " << coeff_count << endl;

    // First copy over.
    destination = encrypted;

    // Prepare for destination
    // Multiply X^index for each ciphertext polynomial
    for (int i = 0; i < encrypted_count; i++) {
        for (int j = 0; j < coeff_mod_count; j++) {
        negacyclic_shift_poly_coeffmod(encrypted.data(i) + (j * coeff_count),
                                        coeff_count, index,
                                        enc_params.coeff_modulus()[j],
                                        destination.data(i) + (j * coeff_count));
        }
    }
}

Ciphertext PirServer::equality_operator(Ciphertext &ct, uint32_t k){
   // cout<<"equality_operator k is"<<k<<endl;
    uint64_t m = 1;
    for(uint32_t i=k; i >0;i--)
    {
        m *= i;
    }
    uint64_t inverse = 0;
    inverse = invert_mod(m, enc_params.plain_modulus());
    vector<Ciphertext> cts;
    for(uint64_t i = 0; i < k;i++)
    {
        Plaintext pt(uint_to_hex_string(&i,std::size_t(1)));
        Ciphertext ct1;
        evaluator_->sub_plain(ct, pt, ct1);
        cts.push_back(ct1);
    }
    Ciphertext result;
    evaluator_->multiply_many(cts, relin_keys,result);
  //  cout<<"multiply many finish"<<endl;
    Plaintext pt1(uint_to_hex_string(&inverse,std::size_t(1)));
    evaluator_->multiply_plain_inplace(result, pt1);
    return result;
}

   vector<Plaintext> PirServer::get_slot_pt()
    {
        vector<Plaintext> pts;
        for(int i =0;i<2020;i++)
        {
            vector<uint64_t> vec(enc_params.poly_modulus_degree(),0);
            vec[i] = 1;
            Plaintext pt;
            encoder_->encode(vec, pt);
            pts.push_back(pt);
        }
        return pts;
    }

    void PirServer::set_galoiskeys(GaloisKeys keys)
    {
        galoisKeys_ = keys;
    }

    void PirServer::set_rotate_galois(GaloisKeys keys)
    {
        rotate_galois_ = keys;
    }
