#include "Poly.hh"
#include <iostream>
#include <openssl/rsa.h>

#define e 65537
#define threshold 3
#define num_nodes 5
#define message 1337

using namespace std;

BN_CTX *bn_ctx;

Poly::Poly(unsigned int deg, const BIGNUM *mod):deg(deg), modulus(NULL){

    coeffs = new BIGNUM *[deg];
    modulus = BN_dup(mod);
    for (unsigned int i=0; i<=deg; i++) {
        coeffs[i] = BN_new();
        BN_rand_range(coeffs[i], modulus);
    }
    return;
}

Poly::~Poly() {
    BN_free(modulus);
    for (unsigned int i=0; i<deg; i++) {
        BN_free(coeffs[i]);
    }
    delete[] coeffs;
}

BIGNUM * Poly::eval(unsigned long x) {
    BN_CTX *bn_ctx = NULL;
    BIGNUM *res = NULL;
    BIGNUM *xval = NULL;
    BIGNUM *tmp = NULL;
    BIGNUM *tmp2 = NULL;    
        
    bn_ctx = BN_CTX_new();
    BN_CTX_init(bn_ctx);
    res = BN_new();
    xval = BN_new();
    BN_zero(res);
    BN_set_word(xval, x);
    tmp = BN_new();
    tmp2 = BN_new();
        
    if (!tmp || !bn_ctx || !res || !xval)
        cout << "Fuck" << endl;
    
    /* For all coeffiecients a compute a*x^i */
    for (unsigned int i=0; i<=deg; i++) {
        BN_set_word(tmp, i);
        BN_mod_exp(tmp2, xval, tmp, modulus, bn_ctx);
        BN_mod_mul(tmp, coeffs[i], tmp2, modulus, bn_ctx);
        BN_mod_add(tmp2, res, tmp, modulus, bn_ctx);
        BN_swap(tmp2, res);
    }
    
    return res;
}

void Poly::set_coeff(unsigned int i, const BIGNUM *coeff) {
    if (i > deg)
        return;
        
    BN_free(coeffs[i]);
    coeffs[i] = BN_dup(coeff);
    
    return;
}

void Poly::print() {
    
    for (unsigned int i=0; i<=deg; i++) {
        cout << BN_bn2hex(coeffs[i]) << " x^" << i;
        if (i != deg)
            cout << " + ";
        else
            cout << " mod " << BN_bn2hex(modulus);
    }
    
    cout << endl;
}

Share::Share(unsigned int _id, const BIGNUM *_value, const BIGNUM *_modulus): id(_id) {
    value = BN_dup(_value);
    modulus = BN_dup(_modulus);
}

Share::~Share() {
    BN_free(value);
    BN_free(modulus);
}

BIGNUM * recover_secret(Share const *share) {
    double l = 1.0;
    BIGNUM *ret = NULL;
    BIGNUM *tmp = NULL;
    
    ret = BN_new();
    tmp = BN_new();

    //cout  << "Share: " << share->id << endl;
    //cout  << BN_bn2hex(share->value) << endl;

    /* Compute the Lagrange coeffient for the base polynomial at x=0
     * l_{i,0} = \Prod{j}{j-1} \forall j \in A, j \neq i where A is the set of
     * cooperating nodes */

    /* In this version we assume that the first t+1 nodes cooperate (i.e. there
     * is no agreement porotcol involved and the set A is known in advance) */
     
    /*FIXME: Division in Z_p is not necessarily feasible (if p is not prime and phi(p) is unknown) */
    for (int i = 1; i<=threshold+1; i++) {
        if (i == share->id)
            continue;
        l *= ((double) i / (i - share->id));
    }

    //cout << "Lagrange coefficient of Thread " << share->id << ": " << l << endl;

    if (l < 0) {
        l *= -1;
        BN_set_word(tmp, l);
        BN_set_negative(tmp, 1);
    } else {
        BN_set_word(tmp, l);
    }
    BN_mod_mul(ret, share->value, tmp, share->modulus, bn_ctx);

    BN_free(tmp);
    return ret;
}

BIGNUM * compute_threshold_sig(Share const *share) {
    double l = 1.0;
    BIGNUM *ret = NULL;
    BIGNUM *tmp = NULL;
    BIGNUM *msg = NULL;

    ret = BN_new();
    tmp = BN_new();
    msg = BN_new();

//    cout  << "Share: " << share->id << endl;
//    cout  << share->value << endl;

    /* Compute the Lagrange coeffient for the base polynomial at x=0
     * l_{i,0} = \Prod{j}{j-1} \forall j \in A, j \neq i where A is the set of
     * cooperating nodes */

    /* In this version we assume that the first t+1 nodes cooperate (i.e. there
     * is no agreement porotcol involved and the set A is known in advance) */
    for (int i = 1; i<=threshold+1; i++) {
        if (i == share->id)
            continue;
        l *= ((double) i / (i - share->id));
    }

//    cout << "Lagrange coefficient of Thread " << share->id << ": " << l << endl;

    if (l < 0) {
        l *= -1;
        BN_set_word(tmp, l);
        BN_set_negative(tmp, 1);
    } else {
        BN_set_word(tmp, l);
    }
    BN_mod_mul(ret, share->value, tmp, share->modulus, bn_ctx);

    BN_set_word(msg, message);
    BN_mod_exp(tmp, msg, ret, share->modulus, bn_ctx);
//    cout << "threshold_sig  for Thread " << share->id << ": " << threshold_sig<< endl;

    BN_free(ret);
    BN_free(msg);
    return tmp;
}


void test() {
    BIGNUM *bn = NULL;
    BIGNUM *res = NULL;
    bn = BN_new();
    BN_set_word(bn, 23);
    Poly *poly = new Poly(4, bn);
    poly->print();
    res = poly->eval(10);
    cout << BN_bn2dec(res) << endl;
    return;
}

int main() {
    BIGNUM *tmp = NULL;
    BIGNUM *recovered = NULL;
    BIGNUM *threshold_sig = NULL;
    RSA *rsa = NULL;
    Share *shares[num_nodes];
    BIGNUM *sig_shares[num_nodes];
    BIGNUM *sec_shares[num_nodes];
    BIGNUM *exponent = NULL;
    
    bn_ctx = BN_CTX_new();
    BN_CTX_init(bn_ctx);
    
    /* Generate RSA key */
    rsa = RSA_generate_key(2048, e, NULL, NULL);
    if (!rsa)
        return -1;

    Poly *poly = new Poly(threshold-1, rsa->n);

    /* Extract secret exponent */
    cout << BN_bn2hex(rsa->d) << endl;
    poly->set_coeff(0, rsa->d);
    poly->print();

    for (int i=0; i<num_nodes; i++) {
        tmp = poly->eval(i + 1);
        shares[i] = new Share(i+1, tmp, rsa->n);
        sig_shares[i] = compute_threshold_sig(shares[i]);
        sec_shares[i] = recover_secret(shares[i]);
    }

    recovered = BN_new();
    BN_zero(recovered);
    threshold_sig = BN_new();
    BN_one(threshold_sig);

    /* Collect the threshold signatures from each thread and combine them */
    for (int i=0; i<=threshold; i++) {
//        combined_sig *= sig_shares[i];
//        combined_sec += sec_shares[i];
        BN_mod_add(tmp, recovered, sec_shares[i], rsa->n, bn_ctx);
        BN_swap(tmp, recovered);
        BN_mod_add(tmp, threshold_sig, sig_shares[i], rsa->n, bn_ctx);
        BN_swap(tmp, threshold_sig);
    }

    cout << BN_bn2hex(recovered) << endl;
    cout << BN_bn2hex(threshold_sig) << endl;
    
    exponent = BN_new();
    BN_set_word(exponent, e);
    
    BN_mod_exp(tmp, threshold_sig, exponent, rsa->n, bn_ctx);
    cout << BN_bn2dec(tmp) << endl;
    delete poly;
    BN_free(tmp);
    BN_free(recovered);
    BN_free(threshold_sig);
    BN_CTX_free(bn_ctx);
    for (int i=0; i<num_nodes; i++) {
        delete shares[i];
        BN_free(sig_shares[i]);
        BN_free(sec_shares[i]);
    }
    return 1;
}
