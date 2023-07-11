#include <seal/seal.h>
#include "../src/helper.h"

using namespace seal;
using namespace std;

int main(){

    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    /*
    We can certainly use BFVDefault coeff_modulus. In later parts of this example,
    we will demonstrate how to choose coeff_modulus that is more useful in BGV.
    */
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 25));


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
    x[0] = -14;
    x[1] = 26;
    x[2] = -3;
    x[3] = 4;

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


    Ciphertext x_square_encrypted;
    evaluator.square(x_encrypted, x_square_encrypted);

    cout << "    + size of encrypted x^2: " << x_square_encrypted.size() << endl;

    cout << "    + noise budget in encrypted x^2: " << decryptor.invariant_noise_budget(x_square_encrypted) << " bits"
         << endl;

    evaluator.relinearize_inplace(x_square_encrypted, relin_keys);
    cout << "    + size of encrypted x^2 after relinearization: " << x_square_encrypted.size() << endl;

    cout << "    + noise budget in encrypted x^2 after relinearization: " << decryptor.invariant_noise_budget(x_square_encrypted) << " bits"
         << endl;

    evaluator.rotate_rows_inplace(x_square_encrypted, 3, galois_keys);

    cout << "    + size of encrypted x^2 after rotation: " << x_square_encrypted.size() << endl;

    cout << "    + noise budget in encrypted x^2 after rotation: " << decryptor.invariant_noise_budget(x_square_encrypted) << " bits"
         << endl;


    
    Plaintext x_decrypted;
    cout << "    + decryption of x_encrypted: ";
    decryptor.decrypt(x_square_encrypted, x_decrypted);

    vector<int64_t> x_result;
    batch_encoder.decode(x_decrypted, x_result);

    print_vector(x_result);
    cout << "" << " ...... Correct." << endl;



    return 0;
}