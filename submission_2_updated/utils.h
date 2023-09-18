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
* ��������
*/

//������
void read_data(matrix<int64_t>& Ma, string& filename, int m, int n);
void read_database_data(matrix<int64_t>& Ma, string& filename, int m, int n);
void read_model(matrix<int64_t>& Ma, string& filename, int m, int n);

//���ܾ���
void encrypt_matrix(matrix<int64_t>& A, vector<Ciphertext>& B, seal::Encryptor& encryptor, seal::BatchEncoder& encoder);
vector<vector<Ciphertext>> encrypt_split_matrix(vector<matrix<int64_t>>& A, seal::Encryptor& encryptor, seal::BatchEncoder& encoder);
vector<Ciphertext> encrypt_matrix_parallel(matrix<int64_t>& A,  seal::Encryptor& encryptor, seal::BatchEncoder& encoder);
vector<vector<Ciphertext>> encrypt_split_matrix_parallel(vector<matrix<int64_t>>& A, seal::Encryptor& encryptor, seal::BatchEncoder& encoder);

//�и����
vector<matrix<int64_t>> split_matrix(matrix<int64_t>& A, seal::EncryptionParameters& parms);

//split u2
void split_vector(matrix<int64_t> &A,vector<vector<int64_t>> &B,seal::EncryptionParameters &parms);

//encrypt vector
void encrypt_vector(vector<vector<int64_t>> &A,vector<seal::Ciphertext> &destination, seal::Encryptor& encryptor, seal::BatchEncoder& encoder);


//��������
void decrypt_vector_result(seal::Ciphertext& result, seal::Decryptor& decryptor, seal::BatchEncoder& encoder);


/*
* �ͻ��˹���
*/

//���ɲ�����Կ��
void client_key_gen();
void client_key_gen( seal::EncryptionParameters& parms, seal::PublicKey& public_key, seal::SecretKey& secret_key, seal::RelinKeys& relin_keys, seal::GaloisKeys& gal_keys);

//�������
void encode_client_matrix(matrix<int64_t>& A, matrix<int64_t>& B, int m, int n);
vector<matrix<int64_t>> encode_split_client_matrix(vector<matrix<int64_t>>& split_matrix, int m, int n);

//Ԥ�����ͻ�������
void preprocessing_split_client_cipher(vector<vector<seal::Ciphertext>>& A, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::BatchEncoder& encoder);

//�������
void allocating_task(matrix<int64_t>& A, vector<matrix<int64_t>>& B);

/*
* ���ݿ�˹���
*/

//Ԥ�������ݿ������
Ciphertext preprocessing_database_cipher(vector<seal::Ciphertext>& A, seal::Ciphertext& u,seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::BatchEncoder& encoder);
void preprocessing_split_database_cipher(vector<vector<seal::Ciphertext>>& A,vector<seal::Ciphertext>& u, vector<Ciphertext>& B, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::BatchEncoder& encoder);

/*
* ����˹���
*/
//��ת��������
void rotate_vector_all(vector<Ciphertext>& v, vector<vector<Ciphertext>>& destination, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys);

//���ľ�������ľ���
void matrix_multiply_vector(vector<seal::Ciphertext>& A, vector<Ciphertext>& rotate_vector, Ciphertext& destination, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys, seal::RelinKeys& relin_keys);
vector<Ciphertext> matrix_multiply_split_vector(vector<vector<seal::Ciphertext>>& A, vector<vector<Ciphertext>>& v, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys, seal::RelinKeys& relin_keys);
void matrix_multiply_split_vector(vector<vector<seal::Ciphertext>>& A, vector<vector<Ciphertext>>& v, vector<Ciphertext> &destination, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys, seal::RelinKeys& relin_keys);
//���������Ľ�����
Ciphertext add_vector_result(vector<Ciphertext>& A, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys);

//����������Ľ�����
void add_allocate_result(vector<Ciphertext>& A, Ciphertext& destination, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys,seal::BatchEncoder &encoder);

long int memory_usage();
