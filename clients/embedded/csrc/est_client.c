/*
 * trustctl-est-client (S8.6): a lightweight POSIX EST (RFC 7030) /simpleenroll client for
 * constrained devices. It has no library dependencies beyond libc and the openssl CLI: it
 * generates the device key + PKCS#10 and parses the issued certs-only PKCS#7 via `openssl`,
 * and speaks HTTP over a POSIX socket. TLS is expected to be terminated by an on-device
 * proxy or added with mbedTLS in a real deployment; this reference keeps the transport
 * minimal so it builds anywhere (cc -O2 -o est_client est_client.c).
 *
 * Usage: est_client <base-url> <workdir>
 *   e.g. est_client http://127.0.0.1:8080 /tmp/enroll
 * On success it writes <workdir>/cert.pem and exits 0.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>

static int sh(const char *cmd) { return system(cmd); }

int main(int argc, char **argv) {
	if (argc < 3) {
		fprintf(stderr, "usage: %s <base-url> <workdir>\n", argv[0]);
		return 2;
	}
	const char *base = argv[1];
	const char *wd = argv[2];
	char cmd[4096], path[2048];

	/* 1. Generate the device key and a PKCS#10 (DER) with openssl. */
	snprintf(cmd, sizeof cmd,
		"openssl req -new -newkey rsa:2048 -nodes -keyout %s/key.pem -outform DER -out %s/csr.der -subj /CN=device-c 2>/dev/null",
		wd, wd);
	if (sh(cmd) != 0) { fprintf(stderr, "est: key/CSR generation failed\n"); return 1; }

	/* 2. base64-encode the CSR (single line) for the EST body. */
	snprintf(cmd, sizeof cmd, "openssl base64 -A -in %s/csr.der -out %s/csr.b64", wd, wd);
	if (sh(cmd) != 0) { fprintf(stderr, "est: base64 of CSR failed\n"); return 1; }

	snprintf(path, sizeof path, "%s/csr.b64", wd);
	FILE *f = fopen(path, "r");
	if (!f) { fprintf(stderr, "est: cannot read CSR\n"); return 1; }
	char body[16384];
	size_t n = fread(body, 1, sizeof body - 1, f);
	fclose(f);
	body[n] = 0;
	while (n && (body[n - 1] == '\n' || body[n - 1] == '\r')) body[--n] = 0;

	/* 3. Parse the base URL (http://host[:port]). */
	char host[256];
	int port = 80;
	if (sscanf(base, "http://%255[^:/]:%d", host, &port) < 1 &&
	    sscanf(base, "http://%255[^:/]", host) < 1) {
		fprintf(stderr, "est: unsupported URL %s\n", base);
		return 1;
	}

	/* 4. Connect. */
	char portstr[16];
	snprintf(portstr, sizeof portstr, "%d", port);
	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, portstr, &hints, &res) != 0) { fprintf(stderr, "est: resolve failed\n"); return 1; }
	int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (fd < 0 || connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
		fprintf(stderr, "est: connect failed\n");
		return 1;
	}
	freeaddrinfo(res);

	/* 5. POST the base64 PKCS#10 to /.well-known/est/simpleenroll (HTTP/1.0, no chunking). */
	char req[20000];
	int reqlen = snprintf(req, sizeof req,
		"POST /.well-known/est/simpleenroll HTTP/1.0\r\n"
		"Host: %s\r\n"
		"Content-Type: application/pkcs10\r\n"
		"Content-Transfer-Encoding: base64\r\n"
		"Content-Length: %zu\r\n"
		"Connection: close\r\n\r\n%s",
		host, n, body);
	if (write(fd, req, (size_t)reqlen) != reqlen) { fprintf(stderr, "est: write failed\n"); close(fd); return 1; }

	/* 6. Read the whole response. */
	char resp[65536];
	size_t total = 0;
	ssize_t r;
	while ((r = read(fd, resp + total, sizeof resp - 1 - total)) > 0) {
		total += (size_t)r;
		if (total >= sizeof resp - 1) break;
	}
	close(fd);
	resp[total] = 0;

	if (strncmp(resp, "HTTP/1.0 200", 12) != 0 && strncmp(resp, "HTTP/1.1 200", 12) != 0) {
		fprintf(stderr, "est: enrollment rejected: %.48s\n", resp);
		return 1;
	}
	char *p = strstr(resp, "\r\n\r\n");
	if (!p) { fprintf(stderr, "est: malformed response\n"); return 1; }
	p += 4;

	/* 7. Decode the certs-only PKCS#7 to cert.pem. */
	snprintf(path, sizeof path, "%s/p7.b64", wd);
	FILE *o = fopen(path, "w");
	if (!o) { fprintf(stderr, "est: cannot write response\n"); return 1; }
	fputs(p, o);
	fclose(o);
	snprintf(cmd, sizeof cmd,
		"openssl base64 -d -A -in %s/p7.b64 -out %s/p7.der && "
		"openssl pkcs7 -inform DER -in %s/p7.der -print_certs -out %s/cert.pem 2>/dev/null",
		wd, wd, wd, wd);
	if (sh(cmd) != 0) { fprintf(stderr, "est: decoding issued certificate failed\n"); return 1; }

	fprintf(stdout, "est: enrolled, certificate at %s/cert.pem\n", wd);
	return 0;
}
