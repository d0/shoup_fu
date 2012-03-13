#include <stdio.h>
#include <stdint.h>
#include <iostream>
#include <pthread.h>
#include <openssl/rsa.h>
#include <NTL/ZZ_pX.h>
#include <NTL/ZZ_p.h>
#include <unistd.h>

#define threshold 3
#define num_nodes 5
#define e 65537
#define message 1337

NTL_CLIENT

class Share { public: int id; ZZ_p value;};

void *node(void *ptr) {
    Share *share = (Share*) ptr;
    double l = 1.0;

    sleep(share->id);
//    cout  << "Thread: " << share->id << endl;
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

    cout << "Lagrange coefficient of Thread " << share->id << ": " << l << endl;

    ZZ_p k = share->value * (long) l;
    ZZ_p m = to_ZZ_p(message);
    ZZ_p threshold_sig = power(m, k.LoopHole());
//    cout << "threshold_sig  for Thread " << share->id << ": " << threshold_sig<< endl;

    ZZ_p *result = new ZZ_p(threshold_sig);
    return (void*) result;
}


int main() {
    RSA *rsa = NULL;
    ZZ_pX poly;
    char *tmp = NULL;
    pthread_t nodes[num_nodes];
    Share *shares[num_nodes];
    void *sig_shares[num_nodes];

    /* Generate RSA key */
    rsa = RSA_generate_key(2048, e, NULL, NULL);
    if (!rsa)
        return -1;

    /* Extract modulus and initalize NTL to use it */
    tmp = BN_bn2dec(rsa->n);
    ZZ_p::init(to_ZZ(tmp));
    free(tmp);

    /* Extract secret exponent */
    ZZ_p secret_exponent;
    tmp = BN_bn2dec(rsa->d);
    secret_exponent = to_ZZ_p(to_ZZ(tmp));

    /* Generate random polynomial of degree t+1 o that f(0) = secret exponent */
    random(poly, threshold + 1);
    SetCoeff(poly, 0, secret_exponent);

//    RSA_print_fp(stdout, rsa, 0);
//    cout << "d = " << BN_bn2dec(rsa->d) << endl;
//    cout << poly << endl;

    /* Generate a thread for every node */
    for (int i=0; i<num_nodes; i++) {
        ZZ_p val = eval(poly, to_ZZ_p(i + 1));
        shares[i] = new Share;
        shares[i]->id = i+1;
        shares[i]->value = val;
        pthread_create(&nodes[i], NULL, node, (void*) shares[i]);
    }

    for (int i=0; i<num_nodes; i++) {
       pthread_join(nodes[i], &sig_shares[i]);
       ZZ_p *tmp = (ZZ_p *) sig_shares[i];
       cout << *tmp;
    }

    if (rsa)
        RSA_free(rsa);
    if (tmp)
        free(tmp);
    for (int i=0; i<num_nodes; i++) {
        delete shares[i];
        delete (ZZ_p*) sig_shares[i];
    }
    return 0;
}
