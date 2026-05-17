#include <stdio.h>
#include "c/envshield.h"

int main() {
    printf("--- C Interceptor Test ---\n");
    char *api_key = envshield_getenv("SECRET_API_KEY");
    if (api_key) {
        printf("C Decrypted SECRET_API_KEY: %s\n", api_key);
        envshield_free(api_key);
    } else {
        printf("Failed to decrypt SECRET_API_KEY\n");
    }

    char *db_pass = envshield_getenv("DB_PASSWORD");
    if (db_pass) {
        printf("C Decrypted DB_PASSWORD: %s\n", db_pass);
        envshield_free(db_pass);
    } else {
        printf("Failed to decrypt DB_PASSWORD\n");
    }

    return 0;
}
