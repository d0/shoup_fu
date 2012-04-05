#ifndef POLY_HH
#define POLY_HH

#include <openssl/bn.h>

class Poly{
public:
    Poly(unsigned int deg, const BIGNUM *modulus);
    ~Poly();
    BIGNUM *eval(unsigned long x);
    void set_coeff(unsigned int i, const BIGNUM *coeff);
    void print();

private:
    unsigned int deg;
    BIGNUM *modulus;
    BIGNUM **coeffs;
};

class Share{
public:
    int id;
    BIGNUM *value;
    BIGNUM *modulus;
    Share(unsigned int _id, const BIGNUM *_value, const BIGNUM *_modulus);
    ~Share();
};

#endif
