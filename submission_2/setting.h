#pragma once
#define poly_modulus_degree_size 8192
#define NUM_THREADS 8
#define CoeffModulus_vector {43,43,44,44,44}
// #define CoeffModulus_vector {34,34,34,34,34}
// #define CoeffModulus_vector {32,32,32,32,32}
#define PlainModulus_size 25
#define batch_size 64
#define client_matirx_row_size 400
#define client_matirx_col_size 16344

#define public_dir  "./../tmp/public"
#define secret_key_dir  "./../tmp/secret_key"

#define client_data_dir "../../CHALLENGE_DATA_DIR/QUERY_SITE_genotypes.txt"
#define database_data_dir "../../CHALLENGE_DATA_DIR/DATABASE_SITE_genotypes.txt"
 #define model_data_dir "../../model/minus_u2.txt"
//#define model_data_dir "../../model/u2.txt"

#define result_dir "./"