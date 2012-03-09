#include <stdio.h>
#include <iostream>
#include <openssl/rsa.h>
#include <NTL/ZZ_pX.h>

#define threshold 3
#define num_nodes 5
#define e 65537

NTL_CLIENT

int main() {
    RSA *rsa = NULL;
    ZZ secret_exponent;
    ZZ_pX poly;
    char *tmp = NULL;

    rsa = RSA_generate_key(2048, e, NULL, NULL);
    if (!rsa)
        goto err;

    tmp = BN_bn2dec(rsa->n);
    ZZ_p::init(to_ZZ(tmp));
    free(tmp);

    tmp = BN_bn2dec(rsa->d);
    secret_exponent = to_ZZ(tmp);

    random(poly, num_nodes);

    RSA_print_fp(stdout, rsa, 0);
    printf("\n");
    printf("\n");
    std::cout << poly;
    printf("\n");
err:
    if (rsa)
        RSA_free(rsa);
    if (tmp)
        free(tmp);
    return 0;
}
