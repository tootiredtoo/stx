#!/bin/bash

set -e

CERT_DIR="certs"

mkdir -p "$CERT_DIR"

echo "Generating private key..."
openssl genpkey -algorithm RSA -out "$CERT_DIR/server.key" -pkeyopt rsa_keygen_bits:2048

echo "Generating self-signed certificate..."
openssl req -new -x509 -key "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" -days 365 \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

echo "Generating DH parameters (this may take a while)..."
openssl dhparam -out "$CERT_DIR/dh2048.pem" 2048

echo "✔ Certificates generated in '$CERT_DIR/'"
