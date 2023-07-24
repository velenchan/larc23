#include"utils.h"
#include"seal/seal.h"
#include"iostream"
#include <omp.h>

using namespace std;
using namespace seal;

int main() {
	omp_set_num_threads(8);
	auto start_time = chrono::high_resolution_clock::now();
	//生成bgv加密参数
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

	/*参数列表*/
	int size_tmp;
	/*客户端*/
	vector<matrix<int64_t>> allocat_matrix_task;//分配矩阵乘法任务
	vector<vector<matrix<int64_t>>> allocate_split_matrix,allocate_split_encode_matrix;//用于存放分配好任务的切割矩阵
	matrix<int64_t> client_matrix;//用于读客户端数据
	vector<matrix<int64_t>> split_matrix_result, encode_split_matrix;//用于存放切割矩阵及编码矩阵的中间变量
	vector<vector<seal::Ciphertext>> client_cipher_matrix;//单条密文数据
	vector<vector<vector<seal::Ciphertext>>> client_cipher_matrix_all;//所有密文数据
	string client_filename = client_data_dir;//客户端文件路径

	/*数据库端*/
	matrix<int64_t> database_matrix;//用于读数据库端数据
	vector<matrix<int64_t>> database_split_matrix;//切割数据库端数据
	vector<vector<seal::Ciphertext>> database_cipher_matrix;//切割矩阵密文数据
	string database_filename = database_data_dir;//客户端文件路径

	/*计算端*/
	vector<seal::Ciphertext> pre_database_cipher;//数据库端预处理结果密文
	vector<seal::Ciphertext> mul_result;//存放计算结果
	vector<vector<seal::Ciphertext>> rotate_vector;//存放旋转完的结果
	vector<vector<Ciphertext>> mul_vector;//存放乘法的中间结果
	vector<Ciphertext> result_vector;//存放每个batch运算之后的计算结果
	seal::Ciphertext result;//存放最后的计算结果


	cout << "----------------- Client --------------------" << endl;
	/*读客户端数据*/
	print_line(__LINE__);
	cout << " Read Client Original Data" << endl;
	read_data(client_matrix, client_filename, 16344, 400);
	client_matrix = client_matrix.transpose();
	cout << "       + Read Client Original Data Already" << endl;
	allocating_task(client_matrix, allocat_matrix_task);
	//cout << allocat_matrix_task.size() << endl;

	
	/*切割矩阵*/
	print_line(__LINE__);
	cout << " Split Client Matrix" << endl;
	allocate_split_matrix.resize(allocat_matrix_task.size());
#pragma omp parallel for
	for (int i = 0; i < allocat_matrix_task.size(); i++) {
		allocat_matrix_task[i].resize(batch_size, 16384);//重置矩阵大小
		allocate_split_matrix[i] =split_matrix(allocat_matrix_task[i], parms);//切割矩阵	
	}
	cout << "       + Split Client Matrix Already" << endl;

	/*编码矩阵*/
	print_line(__LINE__);
	cout << " Encode Client Original Data" << endl;
	size_tmp = allocate_split_matrix.size();
	allocate_split_encode_matrix.resize(size_tmp);
#pragma omp parallel for
	for (int i = 0; i < size_tmp; i++) {
		allocate_split_encode_matrix[i]=encode_split_client_matrix(allocate_split_matrix[i], batch_size, poly_modulus_degree_size);//编码切割矩阵
	}
	cout << "       + Encode Client Original Data Already" << endl;
	

	/*加密数据*/
	print_line(__LINE__);
	cout << " Encrypt Client Original Data" << endl;
	size_tmp = allocate_split_encode_matrix.size();
	client_cipher_matrix_all.resize(size_tmp);
	for (int i = 0; i < size_tmp; i++) {
		client_cipher_matrix_all[i]= encrypte_split_matrix(allocate_split_encode_matrix[i], encryptor, encoder);
	}
	cout << "       + Encrypt Client Original Data Already" << endl;


	cout << "----------------- Database --------------------" << endl;
	/*读数据库端数据*/
	print_line(__LINE__);
	cout << " Read Database Original Data" << endl;
	read_data(database_matrix, database_filename, 16344, 2000);
	database_matrix = database_matrix.transpose();
	cout << "       + Read Database Original Data Already" << endl;

	/*切割矩阵*/
	print_line(__LINE__);
	cout << " Split Database Matrix" << endl;
	database_matrix.resize(2000, 16384);//重置矩阵大小
	database_split_matrix=split_matrix(database_matrix, parms);//切割矩阵
	cout << "       + Split Database Matrix Already" << endl;

	/*加密数据*/
	print_line(__LINE__);
	cout << " Encrypt Database Original Data" << endl;
	database_cipher_matrix=encrypte_split_matrix_parallel(database_split_matrix, encryptor, encoder);
	cout << "       + Encrypt Database Original Data Already" << endl;


	cout << "----------------- Evaluator --------------------" << endl;
	/*进行预处理*/
	/*step1.将数据库端相加并减去2000*/
	print_line(__LINE__);
	cout << " Preprocessing Database Ciphertext Data" << endl;
	preprocessing_split_database_cipher(database_cipher_matrix, pre_database_cipher, parms, evaluator, encoder);
	database_cipher_matrix.clear();//清空数据库数据所占内存
	cout << "       + Preprocessing Database Ciphertext Data Already" << endl;
	cout << "           + Noise budget after add_many: " << decryptor.invariant_noise_budget(pre_database_cipher[0]) << " bits" << endl;
	seal::Ciphertext cipher1;

	/*step.2将客户端数据全部减去1*/
	print_line(__LINE__);
	cout << " Preprocessing Client Ciphertext Data" << endl;
	size_tmp = client_cipher_matrix_all.size();
	//cout << size_tmp << endl;
	for (int i = 0; i < client_cipher_matrix_all.size(); i++) {
		preprocessing_split_client_cipher(client_cipher_matrix_all[i], parms, evaluator, encoder);
	}
	cout << "       + Preprocessing Client Ciphertext Data Already" << endl;
	//cout << "           + Noise budget after add_many: " << decryptor.invariant_noise_budget(client_cipher_matrix[0][0]) << " bits" << endl;

	/*生成旋转密文*/
	print_line(__LINE__);
	cout << " Rotate vector Data" << endl;
	rotate_vector_all(pre_database_cipher, rotate_vector, parms, evaluator, gal_keys);
	cout << "       + Rotate vector Data Already" << endl;

	/*客户端矩阵和向量相乘*/
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

	/*将单条密文的内容相加*/
	print_line(__LINE__);
	cout << " Add Each result Data" << endl;
	for (int i = 0; i < mul_vector.size(); i++) {
		add_vector_result(mul_vector[i], result, evaluator, gal_keys);
		result_vector.push_back(result);
	}
	cout << "       + Add Each result Data Already" << endl;
	cout << "           + Noise budget after computing: " << decryptor.invariant_noise_budget(result) << " bits" << endl;
	

	/*将所有密文结果相加*/
	print_line(__LINE__);
	cout << " Add all result Data" << endl;
	add_allocate_result(result_vector, result, evaluator, gal_keys, encoder);
	cout << "       + Add all result Data Already" << endl;
	cout << "           + Noise budget after computing: " << decryptor.invariant_noise_budget(result) << " bits" << endl;

	/*将结果放入文件*/
	print_line(__LINE__);
	cout << " Write result to file" << endl;
	decrypte_vector_result(result, decryptor, encoder);
	cout << "       + Write result to file Already" << endl;

	auto end_time = chrono::high_resolution_clock::now();
	auto time_diff = chrono::duration_cast<chrono::microseconds>(end_time - start_time);
	cout << "BGV耗时：" << time_diff.count()/1000 << " ms" << "     平均时间：" << time_diff.count() / (400*1000) << " ms" << endl;

}