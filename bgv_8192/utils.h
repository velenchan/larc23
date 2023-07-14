#pragma once
/*
* ʵ��Ԥ��ֵ�Ķ���
* ʵ��ģ�͵Ķ���
* ʵ�ֽ����д
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

//������
void read_data(matrix<uint64_t>& Ma, string& filename, int m, int n);

//�����ľ���
void read_matrix_file(vector<Ciphertext>& A, string filename,seal::SEALContext &context, int start_index, int length);

//д���ĵ��ļ�
void write_data_to_file(vector<seal::Ciphertext>& v, string filename, int start_index);

//���ܾ���
void encrypte_matrix(matrix<uint64_t>& A, vector<Ciphertext>& B, seal::Encryptor& encryptor, seal::BatchEncoder& encoder);


//����ز���
void read_secret_key_and_paramter(seal::EncryptionParameters& parms,seal::SecretKey &secret_key);
void read_paramter_and_public_key(seal::EncryptionParameters& parms, seal::PublicKey& public_key, seal::RelinKeys& relin_keys, seal::GaloisKeys& gal_keys);
void read_paramter_and_public_key(seal::EncryptionParameters& parms, seal::PublicKey& public_key);

/*���ɲ�������*/
void generate_test_data(matrix<uint64_t>& A, int n, int m);
