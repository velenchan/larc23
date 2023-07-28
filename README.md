# Secure Relative Detection in (Forensic) Databases

This project is developed by the LARC team for [iDash 2023 competition Track 1][1] - Secure Relative Detection in (Forensic) Databases. 

## Entities
We have three entities: 
1. A query entity (QE): QE holds  genomes of target individuals, containning $400$ genomes with the genotypes for $16,344$ genetic variants.
2. A database owner (DE): DE contains $2,000$ genomes with genotypes for the same set of $16,344$ variants.
3. A computing entity (CE):   CE performs genome detection using the encrypted data from QE and DE, non-colluding with QE or DE.

## Goal

To decide if any of the query individuals from QE  are related to any individuals in the genomic database from DE.

## Processing Flow

1. QE initializes for a homomorphic encryption (HE) scheme, including generating secret key, public key, and keys for further HE operations.
2. QE using the public key encrypts the private query genotype data.
3. DE using QE's public key encryts the genotype data of the database.
4. CE homomorphically evaluates a query mechanism, using QE's encrypted data and the public information of the HE scheme, and returns an encrypted score for each query individual.
5. QE decrypts the encrypted results.

The encryption, decryption, and homomorphic evaluation use the [BGV][2] scheme implemented in [Microsoft SEAL][3]. 

## Query Mechanism

We, the LARC team, proposed two different mechanisms, which we call Average-Max and Non-Principal Commponent Analysis, respectively. Note that both mechanisums are enlighted by the "[SNP-based measures of relatedness][4]". 

### Notations

- $\bm{Q}\in\mathbb{Z}^{16,344\times 400}$: the query data 
- $\bm{A}\in\mathbb{Z}^{2,000\times 16,344}$: the database data. 
- $\bm{r}\in\mathbb{Z}^{1\times 400}$: the resulting scores for the $400$ query individuals

### Submission 1: Average-Max

The basic idea of this mechanism is to replace max by the negative average, based on the observations on the challenging data. The scores 
$$\bm{r} = \bm{1}_{1\times 2,000}(\bm{A} - \bm{1}_{2,000\times 16,344})\bm{Q}.$$

### Submission 2: Non-Principal Commponent Analysis

The basis idea is to keep only non-principal commponent from the data base. The resulting scores 
$$\bm{r} = (\bm{1}_{1\times 2,000}(10\cdot\bm{A}) - \bm{u}_{1\times 16,344})\bm{Q},$$ 
where $\bm{u}$ is a `principal vector`, which is invariant, even for different queries or different database.

## Compile and run (Ubuntu 22.04.2 LTS)
### Dependencies
- cmake 3.13 or higher
- clang
- openmp
- [Microsoft SEAL](https://github.com/microsoft/seal)

### Compile
Download the source code from GitHub, unzip and enter the repository root directory, and then run the following:

    cd submission_X
    mkdir build
    cd build
    cmake ..
    make

wehre `X` should be specified to `1` for Average-Max or `2` for Non-Principal Component Analysis.
### How to use 

- Query genotype data must be renamed as  `"QUERY_SITE_genotypes.txt"`, and must be put in the  `"CHALLENGE_DATA_DIR"` directory (relative to repository root).
- Database genotype data must be renamed as  `"DATABASE_SITE_genotypes.txt"`, and must be put in the  `"CHALLENGE_DATA_DIR"` directory (relative to repository root).
- Open a terminal, enter the `submission_X/build` directory (relative to repository root, and `X` should specified to `1` or `2`), and run 
    
        ./IDASH23

- The above command produces a file in the the `submission_X/build` directory (relative to repository root, and `X` should specified to `1` or `2`) named `result.txt`. The resulting file consists of $400$ rows and $1$ column. Each row is the score of the corresponding query individual.
































[1]: http://www.humangenomeprivacy.org/2023/competition-tasks.html
[2]: https://doi.org/10.1145/2633600
[3]: https://github.com/microsoft/seal
[4]: https://doi.org/10.1038/nrg3821