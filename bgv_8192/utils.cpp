#include "utils.h"

/*
* ��ԭʼ����
* ���룺����Ma���ļ�·��filename����������m����������n
*/
void read_data(matrix<int64_t>& Ma, string& filename, int m, int n)
{
    fstream in(filename);
    if (!in.is_open())
    {
        cout << "open .txt fail!" << endl;
        return;
    }

    string line;
    Ma.resize(m, n); //ע����Ҫresize����txt�ļ��о����ά�ȶ�Ӧ
    for (int i = 0; i < m; i++)
    {
        getline(in, line);
        int nSPos = 0, nEPos = 0;
        nSPos = line.find('\t', nSPos); //��1��tab��
        nSPos++;
        nSPos = line.find('\t', nSPos); //��2��tab��
        nSPos++;
        nSPos = line.find('\t', nSPos); //��3��tab��
        nSPos++;
        nSPos = line.find('\t', nSPos); //��4��tab��
        // nSPos++;//�������ʼ��λ��
        int j = 0;
        while (1)
        {
            nSPos++;
            nEPos = line.find('\t', nSPos);
            if (nEPos == -1)
            {
                break;
            }
            Ma(i, j) = static_cast<int64_t>(stod(line.substr(nSPos, nEPos - nSPos)));
            j++;
            nSPos = nEPos;
        }
        Ma(i, j) = static_cast<int64_t>(stod(line.substr(nSPos, line.length() - nSPos)));
    }
    in.close();
}

/*
* ��������
* ���룺����A
* ��������ľ���B
*/
void encrypte_matrix(matrix<int64_t>& A, vector<Ciphertext>& B, seal::Encryptor& encryptor, seal::BatchEncoder& encoder)
{
    int row_size = A.get_rows();
    seal::Plaintext plain_tmp;
    seal::Ciphertext cipher_tmp;
    B.resize(row_size);
    
    for (int i = 0; i < row_size; i++) {
        encoder.encode(A.get_row(i), plain_tmp);
        encryptor.encrypt(plain_tmp, cipher_tmp);
        B[i]=cipher_tmp;
    }
}

void encrypte_split_matrix(vector<matrix<int64_t>>& A, vector<vector<Ciphertext>>& destination, seal::Encryptor& encryptor, seal::BatchEncoder& encoder)
{
    vector<Ciphertext> tmp_cipher;
    destination.resize(A.size());
    for (int i = 0; i < A.size(); i++) {
        encrypte_matrix(A[i], tmp_cipher, encryptor, encoder);
        destination[i]=tmp_cipher;
        tmp_cipher.clear();
    }
}

/*
* �и����
* ���룺����A������parms
*/
void split_matrix(matrix<int64_t>& A, vector<matrix<int64_t>>& split_A, seal::EncryptionParameters& parms)
{
    int split_length = parms.poly_modulus_degree();
    int col_size = A.get_cols();
    int row_size = A.get_rows();
    int index = 0;
    matrix<int64_t> tmp_matrix;
    while (index < col_size) {
        int start_index = index;
        int end_index = index + split_length;
        if (index + split_length > col_size) {
            end_index = col_size;
        }
        //cout <<start_index<<"   "<<end_index << endl;
        tmp_matrix.resize(row_size, end_index - start_index);
        for (int i = 0; i < end_index - start_index; i++) {
            tmp_matrix.set_col(i, A.get_col(i + start_index));
            //cout << i << endl;
        }
        index += split_length;
        split_A.push_back(tmp_matrix);
    }
    /*for (int i = 0; i < split_A.size(); i++) {
        cout << split_A.size() << endl;
    }*/
}

/*
* ���ܽ��
*/
void decrypte_vector_result(seal::Ciphertext& result, seal::Decryptor& decryptor, seal::BatchEncoder& encoder)
{
    seal::Plaintext result_dec;
    vector<uint64_t> result_vec;
    decryptor.decrypt(result, result_dec);
    encoder.decode(result_dec, result_vec);
    result_vec.resize(client_matirx_row_size);
    string filename = result_dir;
    ofstream MyFile(filename + "/result.txt", std::ofstream::out | std::ofstream::trunc);

    MyFile << fixed;
    for (int i = 0; i < result_vec.size(); i++)
    {
        MyFile << setprecision(10) << result_vec[i] << endl;
    }
    MyFile.close();
}

void client_key_gen()
{
    cout << endl << "bgv initialization ... " << endl;

    //����ckks���ܲ���
    EncryptionParameters parms(scheme_type::bgv);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    cout << " degree ... yes" << endl;

    //parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 24,24,24,24,24 }));
    cout << " modulus ... yes" << endl;

    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 25));
    cout << " plain modulus ... yes" << endl;

    SEALContext context(parms);
    print_parameters(context);

    KeyGenerator keygen(context);
    cout << " key generator ... yes" << endl;

    SecretKey secret_key = keygen.secret_key();
    cout << " serect key ... yes" << endl;

    Serializable<PublicKey> public_key = keygen.create_public_key();
    cout << " public key ... yes" << endl;

    Serializable<RelinKeys> relin_keys = keygen.create_relin_keys();
    cout << " serializable relinearization key ... yes" << endl;

    // GaloisKeys galois_keys;
    Serializable<GaloisKeys> galois_keys = keygen.create_galois_keys();
    cout << " serializable galois key ... yes" << endl;

    // auto ckks_construction_timing = std::chrono::high_resolution_clock::now() - ckks_construction_start;
    cout << "ckks initialization ... ok" << endl;
    //! end of parameter setting for ckks

    cout << "saving ckks parameters, secret key, public key, relinearization key, and galois key ..." << endl;
    string public_filename = public_dir;
    string secret_filename = secret_key_dir;

    ofstream parms_stream(public_filename + "/parameters", std::ios::out | ios::binary);
    ofstream sk_stream(secret_filename + "/secret_key", std::ios::out | ios::binary);
    ofstream pk_stream(public_filename + "/public_key", std::ios::out | ios::binary);
    ofstream rlk_stream(public_filename + "/relin_key", std::ios::out | ios::binary);
    ofstream gk_stream(public_filename + "/galois_key", std::ios::out | ios::binary);

    auto size = parms.save(parms_stream);
    cout << "encryption parameters wrote " << size << " bytes" << endl;

    size = secret_key.save(sk_stream);
    cout << "secret key wrote " << size << " bytes" << endl;

    size = public_key.save(pk_stream);
    cout << "public key wrote " << size << " bytes" << endl;

    size = relin_keys.save(rlk_stream);
    cout << "relinearization key wrote " << size << " bytes" << endl;

    size = galois_keys.save(gk_stream);
    cout << "galois key wrote " << size << " bytes" << endl;

    cout << "saving bgv parameters, secret key, public key, relinearization key, and galois key ... ok" << endl;
    parms_stream.close();
    sk_stream.close();
    pk_stream.close();
    rlk_stream.close();
    gk_stream.close();
}

void client_key_gen(seal::EncryptionParameters& parms, seal::PublicKey& public_key, seal::SecretKey& secret_key, seal::RelinKeys& relin_keys, seal::GaloisKeys& gal_keys)
{
    cout << endl << "bgv initialization ... " << endl;

    size_t poly_modulus_degree = poly_modulus_degree_size;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    cout << " degree ... yes" << endl;

    //parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, CoeffModulus_vector));
    cout << " modulus ... yes" << endl;

    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, PlainModulus_size));
    cout << " plain modulus ... yes" << endl;

    SEALContext context(parms);
    print_parameters(context);

    KeyGenerator keygen(context);
    cout << " key generator ... yes" << endl;

    secret_key = keygen.secret_key();
    cout << " serect key ... yes" << endl;

    keygen.create_public_key(public_key);
    cout << " public key ... yes" << endl;

    keygen.create_relin_keys(relin_keys);
    cout << " serializable relinearization key ... yes" << endl;

    // GaloisKeys galois_keys;
    keygen.create_galois_keys(gal_keys);
    cout << " serializable galois key ... yes" << endl;

    // auto ckks_construction_timing = std::chrono::high_resolution_clock::now() - ckks_construction_start;
    cout << "ckks initialization ... ok" << endl;
}

/*
* �������
* ���룺����A������m������n
* ������������B
*/
void encode_client_matrix(matrix<int64_t>& A, matrix<int64_t>& B, int m, int n)
{
    /*���þ����С*/
    B.resize(m, n);

    int rotate_outside_size = ceil(sqrt(m));
    int rotate_inside_size = ceil(double(m) / double(rotate_outside_size));

    /*��ת����*/
    int length = 1;


    /*�������*/
    for (int i = 0; i < m; i++) {
        length = (i / rotate_outside_size) * rotate_inside_size;
        for (int j = 0; j < n; j++) {
            if (j < n / 2) {
                B.set(i, j, A.get((j + m - length) % m, (i + j + n / 2 - length) % (n / 2)));
            }
            else {
                B.set(i, j, A.get((j + m - length) % m, (i + j + n / 2 - length) % (n / 2) + (n / 2)));
            }
            //cout << i << "  " << j << "  " << A.get((j+length)% m, (i+j+length) % n) << endl;
        }
    }
}

/*
* �Էָ������б���
*/
void encode_split_client_matrix(vector<matrix<int64_t>>& split_matrix, vector<matrix<int64_t>>& destination_split_matrix, int m, int n)
{
    int split_length = split_matrix[0].get_cols();
    matrix<int64_t> tmp_matrix;
    for (int i = 0; i < split_matrix.size(); i++) {
        encode_client_matrix(split_matrix[i], tmp_matrix, m, split_matrix[i].get_cols());
        destination_split_matrix.push_back(tmp_matrix);
        tmp_matrix.clear();
    }
}

void preprocessing_split_client_cipher(vector<vector<seal::Ciphertext>>& A, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::BatchEncoder& encoder)
{
    seal::Ciphertext cipher_tmp;
    seal::Plaintext plain_tmp;

    vector<int64_t> vector_tmp(parms.poly_modulus_degree(), -1);
    encoder.encode(vector_tmp, plain_tmp);

    for (int i = 0; i < A.size(); i++) {
        for (int j = 0; j < A[i].size(); j++) {
            evaluator.add_plain_inplace(A[i][j], plain_tmp);
        }
    }
}
/*
* ��������
*/
void allocating_task(matrix<int64_t>& A, vector<matrix<int64_t>>& B)
{
    int row_size = A.get_rows();
    int col_size = A.get_cols();
    matrix<int64_t> tmp;
    int size = row_size / batch_size + 1;
    for (int i = 0; i < size; i++) {
        int j = 0;
        tmp.resize(batch_size, col_size);
        while (j < batch_size) {
            //cout << i * batch_size + j << endl;
            if (i * batch_size + j >= row_size) {
                break;
            }
            tmp.set_row(j, A.get_row(i * batch_size+j));
            j++;
        }
        //cout << tmp.get_rows() << "  " << tmp.get_cols() << endl;
        B.push_back(tmp);
    } 
}

void preprocessing_database_cipher(vector<seal::Ciphertext>& A, Ciphertext& B, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::BatchEncoder& encoder)
{
    seal::Ciphertext cipher_tmp;
    seal::Plaintext plain_tmp;
    vector<int64_t> vector_tmp(parms.poly_modulus_degree(), -2000);
    encoder.encode(vector_tmp, plain_tmp);
    evaluator.add_many(A, cipher_tmp);
    evaluator.add_plain(cipher_tmp, plain_tmp, B);
}

void preprocessing_split_database_cipher(vector<vector<seal::Ciphertext>>& A, vector<Ciphertext>& B, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::BatchEncoder& encoder)
{
    Ciphertext tmp;
    for (int i = 0; i < A.size(); i++) {
        preprocessing_database_cipher(A[i], tmp, parms, evaluator, encoder);
        B.push_back(tmp);
    }
}

void rotate_vector_all(vector<Ciphertext>& v, vector<vector<Ciphertext>>& destination, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys)
{
    int rotate_size = batch_size;
    int rotate_outside_size = ceil(sqrt(rotate_size));
    int rotate_inside_size = ceil(double(rotate_size) / double(rotate_outside_size));
    seal::Ciphertext tmp;//����м���
    vector<seal::Ciphertext> rotate_vector(rotate_inside_size);//�����ת��Ľ��

    destination.resize(v.size());
    for (int i = 0; i < v.size(); i++) {
        for (int j = 0; j < rotate_inside_size; j++) {
            //cout << j << endl;
            evaluator.rotate_rows(v[i], j, gal_keys, tmp);
            rotate_vector[j] = tmp;
        }
        destination[i] = rotate_vector;
    }
    

}



/*
* ��������
* ���룺���ľ���A����������v�����destination��������evaluator����ת��Կgal_keys��������Կrelin_keys
* ���������destination
*/
void matrix_multiply_vector(vector<seal::Ciphertext>& A, vector<Ciphertext>& rotate_vector, Ciphertext& destination, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys, seal::RelinKeys& relin_keys)
{
    int rotate_size = A.size();
    int rotate_outside_size = ceil(sqrt(rotate_size));
    int rotate_inside_size = ceil(double(rotate_size) / double(rotate_outside_size));
    //cout << rotate_outside_size << "    " << rotate_inside_size << endl;


    int length = parms.poly_modulus_degree() / 2;
    int sum_rotate = 0;
    int sum_mul = 0;

    seal::Ciphertext tmp;//����м���
    seal::Ciphertext group_cipher;//�ֿ����ĵĽ��
    vector<seal::Ciphertext> result_vector;//������ļ�����

    /*�м���*/
    seal::Plaintext plain_tmp;
    vector<int64_t> vec_tmp;


    /*�����ת*/
    for (int i = 0; i < rotate_outside_size; i++) {

        vector<seal::Ciphertext> cipher_tmp;//�洢�м���
        for (int j = 0; j < rotate_inside_size; j++) {
            //cout << i << "   " << j << endl;
            evaluator.multiply(rotate_vector[j], A[i * rotate_inside_size + j], tmp);
            cipher_tmp.push_back(tmp);
            sum_mul += 1;
        }
        evaluator.add_many(cipher_tmp, tmp);
        evaluator.relinearize_inplace(tmp, relin_keys);
        //cout << rotate_inside_size * i << endl;
        evaluator.rotate_rows_inplace(tmp, rotate_inside_size * i, gal_keys);
        //cout << "   +noise rotate" << decryptor.invariant_noise_budget(tmp) << "bits" << endl;
        result_vector.push_back(tmp);
        /*decryptor.decrypt(tmp, plain_tmp);
        encoder.decode(plain_tmp, vec_tmp);
        print_vector(vec_tmp);*/
        sum_rotate += 1;
    }
    evaluator.add_many(result_vector, group_cipher);
    //cout << "   +noise rotate" << decryptor.invariant_noise_budget(group_cipher) << "bits" << endl;

    /*�������*/
    for (int i = 0; i < log2(length / rotate_size); i++) {
        //cout << pow(2, i) * rotate_size << endl;
        seal::Ciphertext group_tmp;
        evaluator.rotate_rows(group_cipher, pow(2, i) * rotate_size, gal_keys, group_tmp);
        evaluator.add_inplace(group_cipher, group_tmp);
        sum_rotate += 1;
    }
    destination = group_cipher;
    //cout << "��ת������" << sum_rotate << "  �˷�������" << sum_mul << endl;
}

void matrix_multiply_split_vector(vector<vector<seal::Ciphertext>>& A, vector<vector<Ciphertext>>& v, vector<Ciphertext>& destination, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys, seal::RelinKeys& relin_keys)
{
    seal::Ciphertext tmp_result;
    destination.resize(A.size());
    for (int i = 0; i < A.size(); i++) {
        //cout<<i<<"   " << v[i].size() << endl;
        matrix_multiply_vector(A[i], v[i], tmp_result, parms, evaluator, gal_keys, relin_keys);
        destination[i]=tmp_result;
    }
}

void add_vector_result(vector<Ciphertext>& A, Ciphertext& destination, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys)
{
    seal::Ciphertext tmp;
    evaluator.add_many(A, destination);
    evaluator.rotate_columns(destination, gal_keys, tmp);
    evaluator.add_inplace(destination, tmp);
}

void add_allocate_result(vector<Ciphertext>& A, Ciphertext& destination, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys, seal::BatchEncoder& encoder)
{
    seal::Plaintext plain_tmp;
    for (int i = 0; i < A.size(); i++) {
        int start_index = i * batch_size;
        int end_index = (i + 1) * batch_size;
        //cout << start_index << "  " << end_index << endl;
        vector<int64_t> tmp(poly_modulus_degree_size, 0);
        for (int j = start_index; j < end_index; j++) {
            if (j >= client_matirx_row_size) {
                break;
            }
            tmp[j] = -1;
        }
        
        encoder.encode(tmp, plain_tmp);
        evaluator.multiply_plain_inplace(A[i], plain_tmp);
    }
    evaluator.add_many(A, destination);
}
