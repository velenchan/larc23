#pragma once
/*
* 实现预测值的读入
* 实现模型的读入
* 实现结果的写
*/

#include<iostream>
#include<fstream>
#include<iomanip>
#include"matrix.h"
#include<string>
#include"setting.h"
#include"seal/seal.h"

using namespace std;
using namespace seal;

//读数据
void read_data(matrix<uint64_t>& Ma, string& filename, int m, int n);

//读密文矩阵
void read_matrix_file(vector<Ciphertext>& A, string filename,seal::SEALContext &context, int start_index, int length);

//写密文到文件
void write_data_to_file(vector<seal::Ciphertext>& v, string filename, int start_index);

//加密矩阵
void encrypte_matrix(matrix<uint64_t>& A, vector<Ciphertext>& B, seal::Encryptor& encryptor, seal::BatchEncoder& encoder);


//读相关参数
void read_secret_key_and_paramter(seal::EncryptionParameters& parms,seal::SecretKey &secret_key);
void read_paramter_and_public_key(seal::EncryptionParameters& parms, seal::PublicKey& public_key, seal::RelinKeys& relin_keys, seal::GaloisKeys& gal_keys);
void read_paramter_and_public_key(seal::EncryptionParameters& parms, seal::PublicKey& public_key);

/*生成测试数据*/
void generate_test_data(matrix<uint64_t>& A, int n, int m);
