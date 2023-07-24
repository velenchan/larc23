#include"utils.h"
#include"seal/seal.h"
#include"iostream"
#include <omp.h>

using namespace std;
using namespace seal;

int main() {
	omp_set_num_threads(8);
	auto start_time = chrono::high_resolution_clock::now();
	//����bgv���ܲ���
	EncryptionParameters parms(scheme_type::bgv);
	cout << endl << "bgv initialization ... " << endl;

	size_t poly_modulus_degree = poly_modulus_degree_size;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	cout << " degree ... yes" << endl;

	parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, CoeffModulus_vector));
	cout << " modulus ... yes" << endl;

	parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, PlainModulus_size));
	cout << " plain modulus ... yes" << endl;

	SEALContext context(parms);
	print_parameters(context);

	seal::PublicKey public_key;
	seal::SecretKey secret_key;
	seal::GaloisKeys gal_keys;
	seal::RelinKeys relin_keys;
	KeyGenerator keygen(context);
	cout << " key generator ... yes" << endl;
	secret_key = keygen.secret_key();
	cout << " serect key ... yes" << endl;
	keygen.create_public_key(public_key);
	cout << " public key ... yes" << endl;
	keygen.create_relin_keys(relin_keys);
	cout << " serializable relinearization key ... yes" << endl;
	keygen.create_galois_keys(gal_keys);
	cout << " serializable galois key ... yes" << endl;

	cout << "ckks initialization ... ok" << endl;

	Encryptor encryptor(context, public_key);
	Decryptor decryptor(context, secret_key);
	Evaluator evaluator(context);
	BatchEncoder encoder(context);

	/*�����б�*/
	int size_tmp;
	/*�ͻ���*/
	vector<matrix<int64_t>> allocat_matrix_task;//�������˷�����
	vector<vector<matrix<int64_t>>> allocate_split_matrix,allocate_split_encode_matrix;//���ڴ�ŷ����������и����
	matrix<int64_t> client_matrix;//���ڶ��ͻ�������
	vector<matrix<int64_t>> split_matrix_result, encode_split_matrix;//���ڴ���и���󼰱��������м����
	vector<vector<seal::Ciphertext>> client_cipher_matrix;//������������
	vector<vector<vector<seal::Ciphertext>>> client_cipher_matrix_all;//������������
	string client_filename = client_data_dir;//�ͻ����ļ�·��

	/*���ݿ��*/
	matrix<int64_t> database_matrix;//���ڶ����ݿ������
	vector<matrix<int64_t>> database_split_matrix;//�и����ݿ������
	vector<vector<seal::Ciphertext>> database_cipher_matrix;//�и������������
	string database_filename = database_data_dir;//�ͻ����ļ�·��

	/*�����*/
	vector<seal::Ciphertext> pre_database_cipher;//���ݿ��Ԥ����������
	vector<seal::Ciphertext> mul_result;//��ż�����
	vector<vector<seal::Ciphertext>> rotate_vector;//�����ת��Ľ��
	vector<vector<Ciphertext>> mul_vector;//��ų˷����м���
	vector<Ciphertext> result_vector;//���ÿ��batch����֮��ļ�����
	seal::Ciphertext result;//������ļ�����


	cout << "----------------- Client --------------------" << endl;
	/*���ͻ�������*/
	print_line(__LINE__);
	cout << " Read Client Original Data" << endl;
	read_data(client_matrix, client_filename, 16344, 400);
	client_matrix = client_matrix.transpose();
	cout << "       + Read Client Original Data Already" << endl;
	allocating_task(client_matrix, allocat_matrix_task);
	//cout << allocat_matrix_task.size() << endl;

	
	/*�и����*/
	print_line(__LINE__);
	cout << " Split Client Matrix" << endl;
	allocate_split_matrix.resize(allocat_matrix_task.size());
#pragma omp parallel for
	for (int i = 0; i < allocat_matrix_task.size(); i++) {
		allocat_matrix_task[i].resize(batch_size, 16384);//���þ����С
		allocate_split_matrix[i] =split_matrix(allocat_matrix_task[i], parms);//�и����	
	}
	cout << "       + Split Client Matrix Already" << endl;

	/*�������*/
	print_line(__LINE__);
	cout << " Encode Client Original Data" << endl;
	size_tmp = allocate_split_matrix.size();
	allocate_split_encode_matrix.resize(size_tmp);
#pragma omp parallel for
	for (int i = 0; i < size_tmp; i++) {
		allocate_split_encode_matrix[i]=encode_split_client_matrix(allocate_split_matrix[i], batch_size, poly_modulus_degree_size);//�����и����
	}
	cout << "       + Encode Client Original Data Already" << endl;
	

	/*��������*/
	print_line(__LINE__);
	cout << " Encrypt Client Original Data" << endl;
	size_tmp = allocate_split_encode_matrix.size();
	client_cipher_matrix_all.resize(size_tmp);
	for (int i = 0; i < size_tmp; i++) {
		client_cipher_matrix_all[i]= encrypte_split_matrix(allocate_split_encode_matrix[i], encryptor, encoder);
	}
	cout << "       + Encrypt Client Original Data Already" << endl;


	cout << "----------------- Database --------------------" << endl;
	/*�����ݿ������*/
	print_line(__LINE__);
	cout << " Read Database Original Data" << endl;
	read_data(database_matrix, database_filename, 16344, 2000);
	database_matrix = database_matrix.transpose();
	cout << "       + Read Database Original Data Already" << endl;

	/*�и����*/
	print_line(__LINE__);
	cout << " Split Database Matrix" << endl;
	database_matrix.resize(2000, 16384);//���þ����С
	database_split_matrix=split_matrix(database_matrix, parms);//�и����
	cout << "       + Split Database Matrix Already" << endl;

	/*��������*/
	print_line(__LINE__);
	cout << " Encrypt Database Original Data" << endl;
	database_cipher_matrix=encrypte_split_matrix_parallel(database_split_matrix, encryptor, encoder);
	cout << "       + Encrypt Database Original Data Already" << endl;


	cout << "----------------- Evaluator --------------------" << endl;
	/*����Ԥ����*/
	/*step1.�����ݿ����Ӳ���ȥ2000*/
	print_line(__LINE__);
	cout << " Preprocessing Database Ciphertext Data" << endl;
	preprocessing_split_database_cipher(database_cipher_matrix, pre_database_cipher, parms, evaluator, encoder);
	database_cipher_matrix.clear();//������ݿ�������ռ�ڴ�
	cout << "       + Preprocessing Database Ciphertext Data Already" << endl;
	cout << "           + Noise budget after add_many: " << decryptor.invariant_noise_budget(pre_database_cipher[0]) << " bits" << endl;
	seal::Ciphertext cipher1;

	/*step.2���ͻ�������ȫ����ȥ1*/
	print_line(__LINE__);
	cout << " Preprocessing Client Ciphertext Data" << endl;
	size_tmp = client_cipher_matrix_all.size();
	//cout << size_tmp << endl;
	for (int i = 0; i < client_cipher_matrix_all.size(); i++) {
		preprocessing_split_client_cipher(client_cipher_matrix_all[i], parms, evaluator, encoder);
	}
	cout << "       + Preprocessing Client Ciphertext Data Already" << endl;
	//cout << "           + Noise budget after add_many: " << decryptor.invariant_noise_budget(client_cipher_matrix[0][0]) << " bits" << endl;

	/*������ת����*/
	print_line(__LINE__);
	cout << " Rotate vector Data" << endl;
	rotate_vector_all(pre_database_cipher, rotate_vector, parms, evaluator, gal_keys);
	cout << "       + Rotate vector Data Already" << endl;

	/*�ͻ��˾�����������*/
	print_line(__LINE__);
	cout << " Multiply matrix vector Data" << endl;
	size_tmp = client_cipher_matrix_all.size();
	mul_vector.resize(size_tmp);
//#pragma omp parallel for
	for (int i = 0; i < size_tmp; i++) {
		matrix_multiply_split_vector(client_cipher_matrix_all[i], rotate_vector,mul_result, parms, evaluator, gal_keys, relin_keys);
		mul_vector[i] = mul_result;
		//mul_vector[i]=matrix_multiply_split_vector(client_cipher_matrix_all[i], rotate_vector, parms, evaluator, gal_keys, relin_keys);
	}
	cout << "       + Multiply matrix vector Data Already" << endl;
	cout << "           + Noise budget after computing: " << decryptor.invariant_noise_budget(mul_vector[0][0]) << " bits" << endl;

	/*���������ĵ��������*/
	print_line(__LINE__);
	cout << " Add Each result Data" << endl;
	for (int i = 0; i < mul_vector.size(); i++) {
		add_vector_result(mul_vector[i], result, evaluator, gal_keys);
		result_vector.push_back(result);
	}
	cout << "       + Add Each result Data Already" << endl;
	cout << "           + Noise budget after computing: " << decryptor.invariant_noise_budget(result) << " bits" << endl;
	

	/*���������Ľ�����*/
	print_line(__LINE__);
	cout << " Add all result Data" << endl;
	add_allocate_result(result_vector, result, evaluator, gal_keys, encoder);
	cout << "       + Add all result Data Already" << endl;
	cout << "           + Noise budget after computing: " << decryptor.invariant_noise_budget(result) << " bits" << endl;

	/*����������ļ�*/
	print_line(__LINE__);
	cout << " Write result to file" << endl;
	decrypte_vector_result(result, decryptor, encoder);
	cout << "       + Write result to file Already" << endl;

	auto end_time = chrono::high_resolution_clock::now();
	auto time_diff = chrono::duration_cast<chrono::microseconds>(end_time - start_time);
	cout << "BGV��ʱ��" << time_diff.count()/1000 << " ms" << "     ƽ��ʱ�䣺" << time_diff.count() / (400*1000) << " ms" << endl;

}