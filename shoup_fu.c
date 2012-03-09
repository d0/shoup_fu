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
    ZZ_pX poly;
    char *tmp = NULL;

    rsa = RSA_generate_key(2048, e, NULL, NULL);
    if (!rsa)
        return -1;

    tmp = BN_bn2dec(rsa->n);
    ZZ_p::init(to_ZZ(tmp));
    free(tmp);

    ZZ_p secret_exponent;
    tmp = BN_bn2dec(rsa->d);
    secret_exponent = to_ZZ_p(to_ZZ(tmp));

    random(poly, num_nodes);
    SetCoeff(poly, 0, 0);
    SetCoeff(poly, 0, secret_exponent);

    RSA_print_fp(stdout, rsa, 0);
//    printf("d = %s\n", BN_bn2dec(rsa->d));
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
