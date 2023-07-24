#pragma once
#define poly_modulus_degree_size 8192
#define NUM_THREADS 8
#define CoeffModulus_vector {44,44,44,43,43}
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

#define result_dir "./"