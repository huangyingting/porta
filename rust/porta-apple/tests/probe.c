/*
 * Connects through the Porta C interface the way the Apple packet tunnel
 * extension does, prints the session's network settings, and pings a host
 * through the tunnel. Used by scripts/test-apple-ffi.sh.
 *
 * usage: PORTA_TOKEN=... probe SERVER REMOTE-IP CA-PATH IDENTITY-PATH PING-IPV4
 */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "porta.h"

static uint16_t checksum(const uint8_t *data, size_t length) {
  uint32_t sum = 0;
  for (size_t i = 0; i + 1 < length; i += 2) sum += (uint32_t)(data[i] << 8 | data[i + 1]);
  if (length % 2) sum += (uint32_t)data[length - 1] << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (uint16_t)~sum;
}

static int json_string(const char *json, const char *key, char *value, size_t capacity) {
  char pattern[64];
  snprintf(pattern, sizeof pattern, "\"%s\":\"", key);
  const char *start = strstr(json, pattern);
  if (!start) return -1;
  start += strlen(pattern);
  const char *end = strchr(start, '"');
  if (!end || (size_t)(end - start) >= capacity) return -1;
  memcpy(value, start, (size_t)(end - start));
  value[end - start] = 0;
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 6) {
    fprintf(stderr, "usage: %s SERVER REMOTE-IP CA-PATH IDENTITY-PATH PING-IPV4\n", argv[0]);
    return 2;
  }
  char error[512] = {0};
  printf("library %s\n", porta_version());
  PortaIdentity *identity = porta_identity_file(argv[4], "Apple FFI probe", error, sizeof error);
  if (!identity) {
    fprintf(stderr, "identity: %s\n", error);
    return 1;
  }
  printf("device %s\n", porta_identity_device_id(identity));
  PortaConfig config = {
      .server = argv[1],
      .token = getenv("PORTA_TOKEN"),
      .remote_address = argv[2],
      .ca_path = argv[3],
      .thumbprint = NULL,
      .transport = PORTA_TRANSPORT_AUTO,
      .timeout_ms = 10000,
  };
  int32_t status = 0;
  PortaSession *session = porta_connect(&config, identity, &status, error, sizeof error);
  porta_identity_free(identity);
  if (!session) {
    fprintf(stderr, "connect (status %d): %s\n", status, error);
    return status == PORTA_DENIED ? 3 : 1;
  }
  int64_t needed = porta_session_info(session, NULL, 0);
  char *info = malloc((size_t)needed + 1);
  if (!info || porta_session_info(session, info, (size_t)needed + 1) != needed) return 1;
  printf("info %s\n", info);

  char address[64];
  if (json_string(info, "address", address, sizeof address) != 0) return 1;
  *strchr(address, '/') = 0;
  uint8_t packet[64] = {0};
  const char payload[] = "porta ffi";
  size_t length = 28 + sizeof payload - 1;
  packet[0] = 0x45;
  packet[2] = (uint8_t)(length >> 8);
  packet[3] = (uint8_t)length;
  packet[8] = 64;
  packet[9] = 1;
  if (inet_pton(AF_INET, address, packet + 12) != 1 || inet_pton(AF_INET, argv[5], packet + 16) != 1) return 1;
  uint16_t sum = checksum(packet, 20);
  packet[10] = (uint8_t)(sum >> 8);
  packet[11] = (uint8_t)sum;
  packet[20] = 8;
  packet[24] = 0x50;
  packet[25] = 0x46;
  packet[27] = 1;
  memcpy(packet + 28, payload, sizeof payload - 1);
  sum = checksum(packet + 20, length - 20);
  packet[22] = (uint8_t)(sum >> 8);
  packet[23] = (uint8_t)sum;
  if (porta_send(session, packet, length, error, sizeof error) != PORTA_OK) {
    fprintf(stderr, "send: %s\n", error);
    return 1;
  }
  uint8_t reply[2048];
  for (int attempt = 0; attempt < 10; attempt++) {
    int64_t received = porta_receive(session, reply, sizeof reply, 500, error, sizeof error);
    if (received < 0) {
      fprintf(stderr, "receive: %s\n", error);
      return 1;
    }
    if (received >= 28 && reply[9] == 1 && reply[20] == 0 && memcmp(reply + 12, packet + 16, 4) == 0 &&
        reply[24] == 0x50 && reply[25] == 0x46) {
      printf("echo reply from %s\n", argv[5]);
      porta_cancel(session);
      int64_t after = porta_receive(session, reply, sizeof reply, 500, error, sizeof error);
      printf("after cancel %lld\n", (long long)after);
      porta_close(session);
      free(info);
      return after < 0 ? 0 : 1;
    }
  }
  fprintf(stderr, "no echo reply\n");
  return 1;
}
