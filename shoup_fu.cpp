//#include <iostream>
#include <openssl/rsa.h>
#include <NTL/ZZ_pX.h>
#include <NTL/ZZ_p.h>

#define threshold 3
#define num_nodes 5
#define e 65537
#define message 1337

NTL_CLIENT

class Share { public: int id; ZZ_p value;};

ZZ_p lagrange_coefficient(Share const *share) {
    ZZ_p l = ZZ_p();
    l += 1;

//    cout  << "Share: " << share->id << endl;
//    cout  << share->value << endl;

    /* Compute the Lagrange coeffient for the base polynomial at x=0
     * l_{i,0} = \Prod{j}{j-1} \forall j \in A, j \neq i where A is the set of
     * cooperating nodes */

    /* In this version we assume that the first t+1 nodes cooperate (i.e. there
     * is no agreement porotcol involved and the set A is known in advance) */
    for (long i = 1; i<=threshold+1; i++) {
        if (i == share->id)
            continue;
        l *= i;
        l /= i - share->id;
    }

    return l;
}

/**
 * This method is a very basic implementation of Shamir secret sharing.
 * It is used to recover the secret encoded in a polynomial given enough points
 * of the polynomial. To do this, every node computes the right LaGrange
 * coefficient, multiplies it with its private share and returns the result.
 * The results may then be combined to recover the secret. */
ZZ_p shamir_recovery(Share const *share) {
    ZZ_p l = ZZ_p();
    l += 1;

//    cout  << "Share: " << share->id << endl;
//    cout  << share->value << endl;

    /* Compute the Lagrange coeffient for the base polynomial at x=0
     * l_{i,0} = \Prod{j}{j-1} \forall j \in A, j \neq i where A is the set of
     * cooperating nodes */

    /* In this version we assume that the first t+1 nodes cooperate (i.e. there
     * is no agreement porotcol involved and the set A is known in advance) */
    for (long i = 1; i<=threshold+1; i++) {
        if (i == share->id)
            continue;
        l *= i;
        l /= i - share->id;
    }

//    cout << "Lagrange coefficient of Thread " << share->id << ": " << l << endl;

    ZZ_p k = share->value * l;

    return k;
}

/**
 * Compute a very simple RSA threshold signature.
 * In order to do so, we compute the Shamir Share of the private RSA exponent and
 * raise to message by this exponent */
ZZ_p compute_threshold_sig(Share const *share) {
    ZZ_p l = ZZ_p();
    l += 1;

//    cout  << "Share: " << share->id << endl;
//    cout  << share->value << endl;

    /* Compute the Lagrange coeffient for the base polynomial at x=0
     * l_{i,0} = \Prod{j}{j-1} \forall j \in A, j \neq i where A is the set of
     * cooperating nodes */

    /* In this version we assume that the first t+1 nodes cooperate (i.e. there
     * is no agreement porotcol involved and the set A is known in advance) */
    for (long i = 1; i<=threshold+1; i++) {
        if (i == share->id)
            continue;
        l *= i;
        l /= i - share->id;
    }

//    cout << "Lagrange coefficient of Thread " << share->id << ": " << l << endl;

    ZZ_p k = share->value * l;
    ZZ_p threshold_sig = power(to_ZZ_p(message), rep(k));
//    cout << "threshold_sig  for Thread " << share->id << ": " << threshold_sig<< endl;

    return threshold_sig;
}

int main() {
    RSA *rsa = NULL;
    ZZ_pX poly;
    char *tmp = NULL;
    Share *shares[num_nodes];

    /* Generate RSA key */
    rsa = RSA_generate_key(2048, e, NULL, NULL);
    if (!rsa)
        return -1;

    /* Extract modulus and initalize NTL to use it */
    tmp = BN_bn2dec(rsa->n);
    cout << "n = " << tmp << endl << endl;
    ZZ_p::init(to_ZZ(tmp));
    free(tmp);
    ZZ_p sig_shares[num_nodes];
    ZZ_p sec_shares[num_nodes];
    ZZ_p foo[num_nodes];

    /* Extract secret exponent */
    ZZ_p secret_exponent;
    tmp = BN_bn2dec(rsa->d);
    secret_exponent = to_ZZ_p(to_ZZ(tmp));

    /* Generate random polynomial of degree t so that f(0) = secret exponent */
    random(poly, threshold);
    SetCoeff(poly, 0, secret_exponent);

//    RSA_print_fp(stdout, rsa, 0);
    cout << "d = " << tmp << endl << endl;
//    cout << poly << endl;
//    cout << deg(poly) << endl;

    /* Generate a share for every node */
    for (int i=0; i<num_nodes; i++) {
        ZZ_p val = eval(poly, to_ZZ_p(i + 1));
        ZZ_p tmp_sig =  power(to_ZZ_p(message), rep(val));
        shares[i] = new Share;
        shares[i]->id = i+1;
        shares[i]->value = val;
        foo[i] = compute_threshold_sig(shares[i]);
        sig_shares[i] = power(tmp_sig, rep(lagrange_coefficient(shares[i])));
        sec_shares[i] = shamir_recovery(shares[i]);
    }

    ZZ_p combined_sec = to_ZZ_p(0);
    ZZ_p combined_sig = to_ZZ_p(1);
    ZZ_p combined_foo = to_ZZ_p(1);

    /* Collect the threshold signatures from each thread and combine them */
    for (int i=0; i<=threshold; i++) {
        combined_sig *= sig_shares[i];
        combined_foo *= foo[i];
        combined_sec += sec_shares[i];
    }

//    cout << "Expected result: " << power(to_ZZ_p(message), secret_exponent.LoopHole()) << endl;

    cout << "Recovered secret: " << combined_sec << endl;
    if (combined_sec == secret_exponent)
        cout << "Win" << endl;
    else
        cout << "Fail" << endl;

    /* Extract public exponent */
    ZZ_p public_exponent = to_ZZ_p(e);
    ZZ_p sig = power(to_ZZ_p(message), rep(combined_sec));
    ZZ_p recovered_ver = power(sig, rep(public_exponent));
    ZZ_p ver = power(combined_sig, rep(public_exponent));

    /* If everything worked ver should equal message */
    cout << "Recovered Verifier: " << recovered_ver << endl << endl;
    cout << "Threshold Verifier: " << ver << endl << endl;
    cout << "Foo: " << power(combined_foo, rep(public_exponent)) << endl << endl;

    if (rsa)
        RSA_free(rsa);
    if (tmp)
        free(tmp);
    for (int i=0; i<num_nodes; i++) {
        delete shares[i];
    }
    return 0;
}
