#include <stdio.h>
#include <iostream>
#include <pthread.h>
#include <openssl/rsa.h>
#include <NTL/ZZ_pX.h>
#include <NTL/ZZ_p.h>

#define threshold 3
#define num_nodes 5
#define e 65537

NTL_CLIENT

void *node(void *ptr) {
    ZZ_p *share = (ZZ_p*) ptr;
    cout  << *share << endl;
    return NULL;
}


int main() {
    RSA *rsa = NULL;
    ZZ_pX poly;
    char *tmp = NULL;
    pthread_t nodes[num_nodes];

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

    RSA_print_fp(stdout, rsa, 0);
//    printf("d = %s\n", BN_bn2dec(rsa->d));
    printf("\n");
    std::cout << poly;
    printf("\n");

    /* Generate a thread for every node */
    for (int i=0; i<num_nodes; i++) {
        ZZ_p share = eval(poly, to_ZZ_p(i + 1)); //FIXME: Memory leak
        cout << share << endl;
        pthread_create(&nodes[i], NULL, node, (void*) &share);
    }

    for (int i=0; i<num_nodes; i++)
       pthread_join(nodes[i], NULL);

err:
    if (rsa)
        RSA_free(rsa);
    if (tmp)
        free(tmp);
    return 0;
}
