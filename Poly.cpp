#include "Poly.hh"
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/bn.h>

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
    for (unsigned int i=0; i<=deg; i++) {
        BN_free(coeffs[i]);
    }
    delete[] coeffs;
}

BIGNUM * Poly::eval(unsigned long x) {
    BIGNUM *res = NULL;
    BIGNUM *xval = NULL;
    BIGNUM *tmp = NULL;
    BIGNUM *tmp2 = NULL;

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

    BN_free(xval);
    BN_free(tmp);
    BN_free(tmp2);

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
    char *s = NULL;

    for (unsigned int i=0; i<=deg; i++) {
        s = BN_bn2hex(coeffs[i]);
        cout << s << " x^" << i;
        free(s);
        if (i != deg)
            cout << " + ";
        else {
            s = BN_bn2hex(modulus);
            cout << " mod " << s;
            free(s);
        }
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
    BN_free(res);
    BN_free(bn);
    delete poly;
    return;
}

int main() {
    bn_ctx = BN_CTX_new();
    BN_CTX_init(bn_ctx);
    BIGNUM *tmp = NULL, *dec = NULL;
    BIGNUM *recovered = NULL, *threshold_sig = NULL, *sig = NULL, *msg = NULL;
    BIGNUM *p = NULL, *q = NULL, *N = NULL, *e_value = NULL, *d = NULL;
    Share *shares[num_nodes];
    BIGNUM *sig_shares[num_nodes];
    BIGNUM *sec_shares[num_nodes];
    BIGNUM *r0=NULL,*r1=NULL,*r2=NULL;
    char *output = NULL;


    /* Generate RSA key using safe primes */
    p = BN_new();
    BN_generate_prime_ex(p, 1024, 1, NULL, NULL, NULL);
    q = BN_new();
    BN_generate_prime_ex(q, 1024, 1, NULL, NULL, NULL);
    N = BN_new();
    BN_mul(N, p, q, bn_ctx);
    r0 = BN_new();
    r1 = BN_new();
    r2 = BN_new();
    e_value = BN_new();
    d = BN_new();
    BN_set_word(e_value, e);

    /* calculate d */
    BN_sub(r1,p,BN_value_one());    /* p-1 */
    BN_sub(r2,q,BN_value_one());    /* q-1 */
    BN_mul(r0,r1,r2,bn_ctx);   /* (p-1)(q-1) */
    BN_mod_inverse(d,e_value,r0,bn_ctx);  /* d */

    Poly *poly = new Poly(threshold-1, N);

    /* Extract secret exponent */
    output = BN_bn2hex(d);
    cout << "d: " << output << endl << endl;
    free(output);
    poly->set_coeff(0, d);
    poly->print();

    for (int i=0; i<num_nodes; i++) {
        tmp = poly->eval(i + 1);
        shares[i] = new Share(i+1, tmp, N);
        sig_shares[i] = compute_threshold_sig(shares[i]);
        sec_shares[i] = recover_secret(shares[i]);
        BN_free(tmp);
    }

    tmp = BN_new();
    recovered = BN_new();
    BN_zero(recovered);
    threshold_sig = BN_new();
    BN_one(threshold_sig);

    /* Collect the threshold signatures from each thread and combine them */
    for (int i=0; i<=threshold; i++) {
        BN_mod_add(tmp, recovered, sec_shares[i], N, bn_ctx);
        BN_swap(tmp, recovered);
        BN_mod_add(tmp, threshold_sig, sig_shares[i], N, bn_ctx);
        BN_swap(tmp, threshold_sig);
    }

    output = BN_bn2hex(recovered);
    cout << "Recovered secret: " << output << endl << endl;
    free(output);
    if (!BN_cmp(d, recovered))
        cout << "Sucessfully recovered the secret exponent" << endl << endl;
    else
        cout << "Failed to recover the secret exponent" << endl << endl;

    sig = BN_new();
    msg = BN_new();
    dec = BN_new();
    BN_set_word(msg, message);
    BN_mod_exp(sig, msg, d, N, bn_ctx);
    BN_mod_exp(dec, sig, e_value, N, bn_ctx);
    output = BN_bn2hex(sig);
    cout << "Signature: " << output << endl << endl;
    free(output);
    output = BN_bn2dec(dec);
    cout << "Dec: " << output << endl << endl;
    free(output);

    output = BN_bn2hex(threshold_sig);
    cout << "Threshold signature: " << output << endl << endl;
    free(output);

    BN_mod_exp(tmp, threshold_sig, e_value, N, bn_ctx);
    output = BN_bn2hex(tmp);
    cout << "\"Decrypted\" signature: " << output << endl << endl;
    free(output);
    delete poly;
    BN_free(dec);
    BN_free(msg);
    BN_free(sig);
    BN_free(tmp);
    BN_free(recovered);
    BN_free(threshold_sig);
    BN_free(p);
    BN_free(q);
    BN_free(d);
    BN_free(e_value);
    BN_free(N);
    BN_free(r0);
    BN_free(r1);
    BN_free(r2);
    BN_CTX_free(bn_ctx);
    for (int i=0; i<num_nodes; i++) {
        delete shares[i];
        BN_free(sig_shares[i]);
        BN_free(sec_shares[i]);
    }
    return 1;
}
