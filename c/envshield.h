#ifndef ENVSHIELD_H
#define ENVSHIELD_H

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Retrieves the value of an environment variable.
 * 
 * It first checks the native environment. If not found, it checks the encrypted
 * `.env.enc` file and decrypts the variable Just-In-Time (JIT) using the master key.
 * 
 * @param name The name of the environment variable.
 * @return A dynamically allocated string containing the value, or NULL if not found.
 *         The caller MUST free the returned string using envshield_free() to ensure
 *         the memory is securely wiped.
 */
char* envshield_getenv(const char* name);

/**
 * @brief Securely wipes and frees memory returned by envshield_getenv.
 * 
 * This uses memory-safe wiping mechanisms (like explicit_bzero) before calling free().
 * 
 * @param ptr The pointer returned by envshield_getenv.
 */
void envshield_free(char* ptr);

#ifdef ENVSHIELD_OVERRIDE_GETENV
/* Note: overriding getenv changes the return semantics (needs free), 
 * so it is generally unsafe unless the caller is aware.
 * A safer approach is to use envshield_getenv explicitly. */
#define getenv(name) envshield_getenv(name)
#endif

#ifdef __cplusplus
}
#endif

#endif // ENVSHIELD_H
