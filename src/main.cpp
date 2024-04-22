#include "pir.h"
#include "client.h"
#include <iostream>
#include "server.h"
#include <random>
#include <seal/seal.h>
#include <chrono>

using namespace std;
using namespace std::chrono;

int main(int argc, char *argv[]){
    uint64_t number_of_itmes = 8192;
    uint32_t logt = 20;
    uint64_t size_per_item = 1024;
    uint32_t N = 8192;

    EncryptionParameters enc_params(scheme_type::bgv);
    PirParams pir_params;
    cout<<"Main : Generating SEAL PArameters"<<endl;
    gen_encrypt_params(N, logt, enc_params);
    gen_pir_params(number_of_itmes,size_per_item,pir_params);

    
    PirClient pir_client(enc_params,pir_params);
    cout<<"Main : Generating galois_keys"<<endl;
    GaloisKeys galois_keys = pir_client.generate_galois_keys();
    GaloisKeys rotate_galois = pir_client.generate_rotate_galois();
    cout<<"Initializing server"<<endl;
    PirServer pir_server(enc_params,pir_params);
    pir_server.set_galoiskeys(galois_keys);
    pir_server.set_rotate_galois(rotate_galois);
    cout<<"Initializing database"<<endl;
    cout<<"Main: Creating the database with random data "<<endl;

    auto db(make_unique<uint8_t[]>(number_of_itmes*size_per_item));

    random_device rd;
    for(uint64_t i = 0;i<number_of_itmes;i++)
    {
        for(uint64_t j = 0;j<size_per_item;j++)
        {
            uint8_t val = rd() % 256;
            db.get()[i*size_per_item+j] = val;
        }
    }

    cout<<"Main: Starting to process the database"<<endl;
    auto time_predb_s = high_resolution_clock::now();
    pir_server.process_database();
    pir_server.set_database(move(db),number_of_itmes,size_per_item);
    auto time_predb_e = high_resolution_clock::now();
    auto time_predb = duration_cast<microseconds>(time_predb_e - time_predb_s);
    cout<<"database generated!"<<endl;

    cout<<"Generate random query keyword"<<endl;
    // uint64_t field1 = (uint64_t)db.get()[rd() % (number_of_itmes * size_per_item)];
    // cout<<field1<<endl;
    // uint64_t field2 = (uint64_t)db.get()[rd() % (number_of_itmes * size_per_item)];
    // uint64_t field = field1 *100+ field2;
    uint64_t field = rd() % number_of_itmes;
    cout<<"Main : You want to fuzzy query all items containing "<<field<<endl;

    auto time_query_s = high_resolution_clock::now();
    PirQuery query = pir_client.generate_query(field);
    auto time_query_e = high_resolution_clock::now();
    auto time_query = duration_cast<microseconds>(time_query_e - time_query_s);
    cout<<"query generated!"<<endl;
    //cout<<"Main : Query time is "<<time_query.count()<<endl;

    stringstream client_stream;
    stringstream server_stream;
    stringstream relink_stream;

    int relink_size = pir_client.generate_serialized_relinkKey(relink_stream);
    cout<<"Main : Relink size is "<<relink_size<<endl;
    pir_server.deserialize_relinkkeys(relink_stream);

    auto time_s_query_s = high_resolution_clock::now();
    int query_size = pir_client.generate_serialized_query(field,client_stream);
    auto time_s_query_e = high_resolution_clock::now();
    auto time_s_query = duration_cast<microseconds>(time_s_query_e - time_s_query_s);
    cout<<"query serialized!"<<endl;
    //cout<<"Main : Serialization time is "<<time_s_query.count()<<endl;

    auto time_desierial_s = high_resolution_clock::now();
    PirQuery query2 = pir_server.deserialize_query(client_stream);
    auto time_desierial_e = high_resolution_clock::now();
    auto time_desierial = duration_cast<microseconds>(time_desierial_e - time_desierial_s);
    cout<<"Query deserialized!"<<endl;
    //cout<<"Main : Deserialization time is "<<time_desierial.count()<<endl;
   

   auto time_server_s = high_resolution_clock::now();
   PirReply reply = pir_server.generate_reply(query2);
   auto time_server_e = high_resolution_clock::now();
   auto time_server = duration_cast<microseconds>(time_server_e - time_server_s);
   cout<<"Reply generated!"<<endl;
   //cout<<"Main : Server time is "<<time_server.count()<<endl;

   int reply_size = pir_server.serialize_reply(reply,server_stream);

    vector<uint8_t> elems = pir_client.decode_reply(reply);
    for(uint64_t i = 0;i<elems.size();i++)
    {
        cout<<(int)elems[i]<<" ";
    }
    cout<<endl;

   cout<<"Main: PIR result conrrect!"<<endl;
   cout<<"Main: PIR predatabase time is "<<ceil(time_predb.count()/1000)<<endl;
   cout<<"Main: PIRClient query time is "<<ceil(time_query.count()/1000)<<endl;
   cout<<"Main: PIRClient serialization time is "<<ceil(time_s_query.count()/1000)<<endl;
   cout<<"Main: PIRClient deserialization time is "<<ceil(time_desierial.count()/1000)<<endl;
   cout<<"Main: PIRServer reply time is "<<ceil(time_server.count()/1000)<<endl;
   cout<<"Main: Query size is "<<query_size<<endl;
   cout<<"Main: Reply size is "<<reply_size<<endl;

   return 0;



}
