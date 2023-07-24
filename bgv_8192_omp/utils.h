#pragma once
#include<iostream>
#include<fstream>
#include<iomanip>
#include"matrix.h"
#include<string>
#include"setting.h"
#include"seal/seal.h"
#include"filesystem"
#include "helper.h"
#include<omp.h>

using namespace std;
using namespace seal;

/*
* 公共功能
*/

//读数据
void read_data(matrix<int64_t>& Ma, string& filename, int m, int n);

//加密矩阵
void encrypte_matrix(matrix<int64_t>& A, vector<Ciphertext>& B, seal::Encryptor& encryptor, seal::BatchEncoder& encoder);
vector<vector<Ciphertext>> encrypte_split_matrix(vector<matrix<int64_t>>& A, seal::Encryptor& encryptor, seal::BatchEncoder& encoder);
vector<Ciphertext> encrypte_matrix_parallel(matrix<int64_t>& A,  seal::Encryptor& encryptor, seal::BatchEncoder& encoder);
vector<vector<Ciphertext>> encrypte_split_matrix_parallel(vector<matrix<int64_t>>& A, seal::Encryptor& encryptor, seal::BatchEncoder& encoder);

//切割矩阵
vector<matrix<int64_t>> split_matrix(matrix<int64_t>& A, seal::EncryptionParameters& parms);

//解密密文
void decrypte_vector_result(seal::Ciphertext& result, seal::Decryptor& decryptor, seal::BatchEncoder& encoder);


/*
* 客户端功能
*/

//生成并构造钥匙
void client_key_gen();
void client_key_gen( seal::EncryptionParameters& parms, seal::PublicKey& public_key, seal::SecretKey& secret_key, seal::RelinKeys& relin_keys, seal::GaloisKeys& gal_keys);

//编码矩阵
void encode_client_matrix(matrix<int64_t>& A, matrix<int64_t>& B, int m, int n);
vector<matrix<int64_t>> encode_split_client_matrix(vector<matrix<int64_t>>& split_matrix, int m, int n);

//预处理客户端密文
void preprocessing_split_client_cipher(vector<vector<seal::Ciphertext>>& A, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::BatchEncoder& encoder);

//分配矩阵
void allocating_task(matrix<int64_t>& A, vector<matrix<int64_t>>& B);

/*
* 数据库端功能
*/

//预处理数据库端密文
Ciphertext preprocessing_database_cipher(vector<seal::Ciphertext>& A, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::BatchEncoder& encoder);
void preprocessing_split_database_cipher(vector<vector<seal::Ciphertext>>& A, vector<Ciphertext>& B, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::BatchEncoder& encoder);

/*
* 计算端功能
*/
//旋转所有密文
void rotate_vector_all(vector<Ciphertext>& v, vector<vector<Ciphertext>>& destination, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys);

//密文矩阵乘密文矩阵
void matrix_multiply_vector(vector<seal::Ciphertext>& A, vector<Ciphertext>& rotate_vector, Ciphertext& destination, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys, seal::RelinKeys& relin_keys);
vector<Ciphertext> matrix_multiply_split_vector(vector<vector<seal::Ciphertext>>& A, vector<vector<Ciphertext>>& v, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys, seal::RelinKeys& relin_keys);
void matrix_multiply_split_vector(vector<vector<seal::Ciphertext>>& A, vector<vector<Ciphertext>>& v, vector<Ciphertext> &destination, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys, seal::RelinKeys& relin_keys);
//将单条密文结果相加
void add_vector_result(vector<Ciphertext>& A, Ciphertext& destination, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys);

//将所有任务的结果相加
void add_allocate_result(vector<Ciphertext>& A, Ciphertext& destination, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys,seal::BatchEncoder &encoder);
