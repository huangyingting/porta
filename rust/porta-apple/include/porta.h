/*
 * Porta tunnel C interface, for the macOS and iOS packet tunnel extension.
 *
 * Build libporta.a with the porta-apple crate (see apple/README.md). All
 * functions may be called from any thread. Strings are NUL-terminated UTF-8.
 * Errors are written into caller buffers; account denials start with
 * "account-denied:CODE:".
 */
#ifndef PORTA_H
#define PORTA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PORTA_OK 0
/* The tunnel failed in a way that reconnecting may fix. */
#define PORTA_RETRYABLE (-1)
/* Reconnecting with the same settings will fail again. */
#define PORTA_PERMANENT (-2)
/* The gateway refused the account or device; see the error text. */
#define PORTA_DENIED (-3)

#define PORTA_TRANSPORT_AUTO 0
#define PORTA_TRANSPORT_HTTP2 2
#define PORTA_TRANSPORT_HTTP3 3

typedef struct PortaIdentity PortaIdentity;
typedef struct PortaSession PortaSession;

/*
 * Signs message with the device's P-256 key (ECDSA over SHA-256, such as
 * kSecKeyAlgorithmECDSASignatureMessageX962SHA256) and writes the DER
 * signature. Returns 0 on success.
 */
typedef int32_t (*PortaSignCallback)(void *context, const uint8_t *message,
                                     size_t message_length, uint8_t *signature,
                                     size_t signature_capacity,
                                     size_t *signature_length);

/* What a session connects to; optional strings may be NULL. */
typedef struct PortaConfig {
  /* Gateway origin, such as "https://vpn.example.com:8443". */
  const char *server;
  const char *token;
  /* Numeric gateway address to dial instead of resolving server. */
  const char *remote_address;
  /* PEM CA certificate for a privately signed gateway. */
  const char *ca_path;
  /* SHA-256 thumbprint the gateway certificate must match. */
  const char *thumbprint;
  /* One of the PORTA_TRANSPORT_ values. */
  uint32_t transport;
  /* Connection deadline; 0 means 15 seconds. */
  uint32_t timeout_ms;
} PortaConfig;

/* The library version, a static string. */
const char *porta_version(void);

/* Loads the device key from path, creating it on first use; NULL on error. */
PortaIdentity *porta_identity_file(const char *path, const char *device_name,
                                   char *error, size_t error_capacity);

/*
 * An identity whose key the app keeps, such as a Secure Enclave key.
 * public_key is its DER SubjectPublicKeyInfo. context is passed back to sign
 * and must outlive the identity and every session connected with it.
 */
PortaIdentity *porta_identity_external(const uint8_t *public_key,
                                       size_t public_key_length,
                                       const char *device_name,
                                       PortaSignCallback sign, void *context,
                                       char *error, size_t error_capacity);

/* The device ID ("d-..."), valid until the identity is freed. */
const char *porta_identity_device_id(const PortaIdentity *identity);

/* Frees an identity; sessions connected with it keep working. */
void porta_identity_free(PortaIdentity *identity);

/*
 * Connects a tunnel. Returns NULL and writes error on failure; status, if
 * not NULL, receives PORTA_OK or the failure class.
 */
PortaSession *porta_connect(const PortaConfig *config,
                            const PortaIdentity *identity, int32_t *status,
                            char *error, size_t error_capacity);

/*
 * Writes the session's network settings as JSON and returns the length the
 * JSON needs without the NUL; retry with a larger buffer when the result is
 * not smaller than capacity. The object holds "address" (IPv4 /32),
 * "gateway", "address6" (/128 or null), "dns", "mtu", "transport",
 * "routes" and "routes6" (split-tunnel prefixes; empty for a full tunnel),
 * "dnsDomains", "fullTunnel" and "account" limits.
 */
int64_t porta_session_info(const PortaSession *session, char *buffer,
                           size_t capacity);

/* Sends one IP packet into the tunnel; PORTA_OK or a failure class. */
int32_t porta_send(const PortaSession *session, const uint8_t *packet,
                   size_t length, char *error, size_t error_capacity);

/*
 * Waits up to timeout_ms for an IP packet and copies it into buffer.
 * Returns its length, 0 on timeout, or a negative failure class.
 */
int64_t porta_receive(const PortaSession *session, uint8_t *buffer,
                      size_t capacity, uint32_t timeout_ms, char *error,
                      size_t error_capacity);

/* Ends the tunnel; blocked and later receives fail. Free with porta_close. */
void porta_cancel(const PortaSession *session);

/* Closes and frees a session; no other call on it may run concurrently. */
void porta_close(PortaSession *session);

#ifdef __cplusplus
}
#endif

#endif /* PORTA_H */
