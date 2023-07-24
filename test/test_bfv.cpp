#include <chrono>
#include <seal/seal.h>
#include "../src/helper.h"

using namespace seal;
using namespace std;

int main(){

    // EncryptionParameters parms(scheme_type::bgv);
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    /*
    We can certainly use BFVDefault coeff_modulus. In later parts of this example,
    we will demonstrate how to choose coeff_modulus that is more useful in BGV.
    */
    // parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {22, 22, 22, 22, 21}));
    // parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {26, 26, 26, 26, 26}));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 16));


    SEALContext context(parms);

    print_line(__LINE__);
    cout << "Set encryption parameters and print" << endl;
    print_parameters(context);

    cout << "Parameter validation (success): " << context.parameter_error_message() << endl;

    cout << endl;
    // cout << "~~~~~~ A naive way to calculate 4(x^2+1)(x+1)^2. ~~~~~~" << endl;

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    Encryptor encryptor(context, public_key);
    
    Evaluator evaluator(context);

    Decryptor decryptor(context, secret_key);

    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    BatchEncoder batch_encoder(context);

    cout << "still ok..." << endl;

    size_t slot_count = batch_encoder.slot_count();
    cout << "the number of slots: " << slot_count << endl;



    vector<int64_t> x(slot_count, 0);
    // x[0] = -16769024;
    x[0] = -1;
    x[1] = 1;
    x[2] = -1;
    x[3] = 1;
    x[slot_count-1] = 5;
    x[slot_count-2] = 7;
    x[slot_count-3] = 11;
    x[slot_count-4] = 13;

    cout << "Input plaintext matrix:" << endl;
    print_vector(x);
    Plaintext x_plain;
    cout << "Encode plaintext matrix to x_plain:" << endl;
    batch_encoder.encode(x, x_plain);


    print_line(__LINE__);
    Ciphertext x_encrypted;
    cout << "Encrypt x_plain to x_encrypted." << endl;
    encryptor.encrypt(x_plain, x_encrypted);

    cout << "    + size of freshly encrypted x: " << x_encrypted.size() << endl;

    cout << "    + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(x_encrypted) << " bits"
         << endl;


    auto t_size = 0;
    for (size_t i = 0; i<4450; i++){
        string file_name = "encrypted_result";
        ofstream enc_result_stream(file_name, ios::binary);
        auto size_ = x_encrypted.save(enc_result_stream);
        t_size += size_;
        enc_result_stream.close();
    }
    cout << "4450 fresh ciphertexts is of size " << t_size << " bytes" << endl;

     Plaintext x_decrypted;
     vector<int64_t> x_result;
     cout << "    + decryption of x_encrypted: ";
     decryptor.decrypt(x_encrypted, x_decrypted);
     batch_encoder.decode(x_decrypted, x_result);
     print_vector(x_result);
     cout << "" << " ...... Correct." << endl;

     Plaintext plain_two_thousand;
     vector<int64_t> two_thousand;
     for (size_t i = 0; i < slot_count; i++){
          two_thousand.push_back(2);
     }
     batch_encoder.encode(two_thousand, plain_two_thousand);
     evaluator.multiply_plain_inplace(x_encrypted, plain_two_thousand);

     cout << "    + noise budget in encrypted x after multiplying 2000: " << decryptor.invariant_noise_budget(x_encrypted) << " bits"
         << endl;


     cout << "    + decryption of x_encrypted after multiplying 2000: ";
     decryptor.decrypt(x_encrypted, x_decrypted);
     batch_encoder.decode(x_decrypted, x_result);
     print_vector(x_result);
     cout << "" << " ...... Correct." << endl;


    auto local_beginning = std::chrono::high_resolution_clock::now();
    for(size_t i = 0; i < 100; i++){
        Ciphertext x_square_encrypted;
        evaluator.multiply(x_encrypted, x_encrypted, x_square_encrypted);
    }
    auto local_timing = std::chrono::high_resolution_clock::now() - local_beginning;
    cout << "   + multiplication ... costs: " << (double)std::chrono::duration_cast<std::chrono::microseconds>(local_timing).count() / 1e6 << " seconds." << endl;


    Ciphertext x_square_encrypted;
    evaluator.square(x_encrypted, x_square_encrypted);
    cout << "    + size of encrypted x^2: " << x_square_encrypted.size() << endl;

    cout << "    + noise budget in encrypted x^2: " << decryptor.invariant_noise_budget(x_square_encrypted) << " bits"
         << endl;

    evaluator.relinearize_inplace(x_square_encrypted, relin_keys);
    cout << "    + size of encrypted x^2 after relinearization: " << x_square_encrypted.size() << endl;

    cout << "    + noise budget in encrypted x^2 after relinearization: " << decryptor.invariant_noise_budget(x_square_encrypted) << " bits"
         << endl;


     cout << "    + decryption of x_square_encrypted after relinearization: ";
     decryptor.decrypt(x_square_encrypted, x_decrypted);
     batch_encoder.decode(x_decrypted, x_result);
     print_vector(x_result);
     cout << "" << " ...... Correct." << endl;

    local_beginning = std::chrono::high_resolution_clock::now();
    for(size_t i = 0; i < 1; i++){
        // evaluator.rotate_columns_inplace(x_square_encrypted, galois_keys);
        // evaluator.rotate_rows_inplace(x_square_encrypted, i % slot_count/2, galois_keys);
        evaluator.rotate_rows_inplace(x_square_encrypted, 3, galois_keys);
    }
    local_timing = std::chrono::high_resolution_clock::now() - local_beginning;
    cout << "   + rotation ... costs: " << (double)std::chrono::duration_cast<std::chrono::microseconds>(local_timing).count() / 1e6 << " seconds." << endl;

     cout << "    + size of encrypted x^2 after rotation: " << x_square_encrypted.size() << endl;

     cout << "    + noise budget in encrypted x^2 after rotation: " << decryptor.invariant_noise_budget(x_square_encrypted) << " bits"
         << endl;


    
    
    cout << "    + decryption of x_encrypted after rotations: ";
    decryptor.decrypt(x_square_encrypted, x_decrypted);
    batch_encoder.decode(x_decrypted, x_result);
    print_vector(x_result);
    cout << "" << " ...... Correct." << endl;



    return 0;

}