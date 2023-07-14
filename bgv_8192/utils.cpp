#include "utils.h"

/*
* 读原始数据
* 输入：矩阵Ma，文件路径filename，矩阵行数m，矩阵列数n
*/
void read_data(matrix<uint64_t>& Ma, string& filename,int m,int n)
{
    fstream in(filename);
    if (!in.is_open())
    {
        cout << "open .txt fail!" << endl;
        return;
    }

    string line;
    Ma.resize(m, n); //注意需要resize，和txt文件中矩阵的维度对应
    for (int i = 0; i < m; i++)
    {
        getline(in, line);
        int nSPos = 0, nEPos = 0;
        nSPos = line.find('\t', nSPos); //第1个tab键
        nSPos++;
        nSPos = line.find('\t', nSPos); //第2个tab键
        nSPos++;
        nSPos = line.find('\t', nSPos); //第3个tab键
        nSPos++;
        nSPos = line.find('\t', nSPos); //第4个tab键
        // nSPos++;//到第五项开始的位置
        int j = 0;
        while (1)
        {
            nSPos++;
            nEPos = line.find('\t', nSPos);
            if (nEPos == -1)
            {
                break;
            }
            Ma(i, j) = static_cast<uint64_t>(stod(line.substr(nSPos, nEPos - nSPos)));
            j++;
            nSPos = nEPos;
        }
        Ma(i, j) = static_cast<uint64_t>(stod(line.substr(nSPos, line.length() - nSPos)));
    }
    in.close();
}


/*
* 从文件中读密文矩阵数据
* 输入：密文矩阵A，文件路径filename，起始位置start_index，长度length
*/
void read_matrix_file(vector<Ciphertext>& A, string filename,seal::SEALContext &context, int start_index, int length)
{
    A.resize(length);
    for (int i = start_index; i < length + start_index; i++) {
        ifstream vector_stream(filename + "/matrix_v" + to_string(i) + ".bin", ios::binary);
        A[i].load(context, vector_stream);
        vector_stream.seekg(0, vector_stream.beg);
    }
}


/*
* 写密文数据到文件中
* 输入：密文矩阵A，文件路径filename，起始序列：start_index
*/
void write_data_to_file(vector<seal::Ciphertext>& v, string filename, int start_index)
{
    int length = v.size();
    long long all_size = 0;
    compr_mode_type compr_mode_zstd = compr_mode_type::zstd;//指定压缩方式
    for (int i = 0; i < v.size(); i++) {
        ofstream vector_stream(filename + "/matrix_v" + to_string(start_index+i) + ".bin", ios::binary);
        auto size = v[i].save(vector_stream);
        vector_stream.close();
        all_size += size;
    }

}

/*
* 加密数据
* 输入：矩阵A
* 输出：密文矩阵B
*/
void encrypte_matrix(matrix<uint64_t>& A, vector<Ciphertext>& B, seal::Encryptor& encryptor, seal::BatchEncoder& encoder)
{
    int row_size = A.get_rows();
    seal::Plaintext plain_tmp;
    seal::Ciphertext cipher_tmp;
    for (int i = 0; i < row_size; i++) {
        encoder.encode(A.get_row(i), plain_tmp);
        encryptor.encrypt(plain_tmp, cipher_tmp);
        B.push_back(cipher_tmp);
    }
}

void read_secret_key_and_paramter(seal::EncryptionParameters& parms, seal::SecretKey& secret_key)
{
    string public_filename = public_dir;
    string secret_filename = secret_key_dir;

    ifstream parms_stream(public_filename + "/parameters", ios::binary);
    ifstream sk_stream(secret_filename + "/secret_key", ios::binary);

    parms.load(parms_stream);
    parms_stream.seekg(0, parms_stream.beg);
    SEALContext context(parms);
    secret_key.load(context, sk_stream);
    sk_stream.seekg(0, sk_stream.beg);

    parms_stream.close();
    sk_stream.close();
}

void read_paramter_and_public_key(seal::EncryptionParameters& parms, seal::PublicKey& public_key, seal::RelinKeys& relin_keys, seal::GaloisKeys& gal_keys)
{
    string public_filename = public_dir;

    ifstream parms_stream(public_filename + "/parameters", ios::binary);
    ifstream pk_stream(public_filename + "/public_key", ios::binary);
    ifstream rlk_stream(public_filename + "/relin_key", ios::binary);
    ifstream gal_stream(public_filename + "/galois_key", ios::binary);

    parms.load(parms_stream);
    parms_stream.seekg(0, parms_stream.beg);

    SEALContext context(parms);
    public_key.load(context, pk_stream);
    pk_stream.seekg(0, pk_stream.beg);

    relin_keys.load(context, rlk_stream);
    rlk_stream.seekg(0, rlk_stream.beg);

    gal_keys.load(context, gal_stream);
    gal_stream.seekg(0, gal_stream.beg);

    parms_stream.close();
    pk_stream.close();
    rlk_stream.close();
    gal_stream.close();

    cout << "       + Read param already" << endl;
}

void read_paramter_and_public_key(seal::EncryptionParameters& parms, seal::PublicKey& public_key)
{
    string public_filename = public_dir;

    ifstream parms_stream(public_filename + "/parameters", ios::binary);
    ifstream pk_stream(public_filename + "/public_key", ios::binary);

    parms.load(parms_stream);
    parms_stream.seekg(0, parms_stream.beg);

    SEALContext context(parms);
    public_key.load(context, pk_stream);
    pk_stream.seekg(0, pk_stream.beg);

    parms_stream.close();
    pk_stream.close();

    cout << "       + Read param already" << endl;
}

void generate_test_data(matrix<uint64_t>& A, int n, int m) {
    A.resize(n, m);
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < m; j++) {
            A.set(i, j, 1);
        }
    }
}
