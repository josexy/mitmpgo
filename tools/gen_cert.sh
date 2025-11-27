#!/bin/bash
set -euo pipefail

# Default configuration
CA_DOMAIN=${CA_DOMAIN:-"example.ca.com"}
# Supports multiple domains and IPs, separated by commas
DOMAINS=${DOMAINS:-"localhost,127.0.0.1"}
IPS=${IPS:-"127.0.0.1"}
OUTDIR=${OUTDIR:-"certs"}
DAYS=${DAYS:-3650}
KEY_SIZE=${KEY_SIZE:-2048}
COUNTRY=${COUNTRY:-"CN"}
LOCATION=${LOCATION:-"Beijing"}

# Check for openssl
command -v openssl >/dev/null 2>&1 || { echo "openssl is required but not installed"; exit 1; }

# Determine openssl configuration file location
if [[ $(uname -s) == "Darwin" ]]; then
    OPENSSL_CONF=/System/Library/OpenSSL/openssl.cnf
else
    OPENSSL_CONF=/etc/ssl/openssl.cnf
fi
[ ! -f "$OPENSSL_CONF" ] && { echo "Cannot find OpenSSL configuration file: $OPENSSL_CONF"; exit 1; }

# Create output directory
mkdir -p "$OUTDIR"
chmod 700 "$OUTDIR"

generate_key() {
    local name=$1
    echo "Generating ${name} private key..."
    openssl genrsa -out "${OUTDIR}/${name}.key" "$KEY_SIZE"
    chmod 600 "${OUTDIR}/${name}.key"
}

generate_san_list() {
    local dns_list=$1
    local ip_list=$2
    local san_list=""

    # Process DNS list
    IFS=',' read -ra DNS_ARRAY <<< "$dns_list"
    local dns_count=1
    for dns in "${DNS_ARRAY[@]}"; do
        [ -n "$san_list" ] && san_list+=", "
        san_list+="DNS.${dns_count}:${dns}"
        ((dns_count++))
    done

    # Process IP list
    IFS=',' read -ra IP_ARRAY <<< "$ip_list"
    local ip_count=1
    for ip in "${IP_ARRAY[@]}"; do
        [ -n "$san_list" ] && san_list+=", "
        san_list+="IP.${ip_count}:${ip}"
        ((ip_count++))
    done

    echo "$san_list"
}

generate_cert() {
    local name=$1
    local is_ca=${2:-false}
    echo "Generating ${name} certificate..."

    if [ "$is_ca" = true ]; then
        openssl req -x509 -new -nodes \
            -key "${OUTDIR}/${name}.key" \
            -subj "/C=${COUNTRY}/L=${LOCATION}/CN=${CA_DOMAIN}" \
            -days "$DAYS" \
            -out "${OUTDIR}/${name}.crt"
    else
        # Get SAN list
        local san_list=$(generate_san_list "$DOMAINS" "$IPS")

        # Generate CSR
        openssl req -new -key "${OUTDIR}/${name}.key" \
            -subj "/C=${COUNTRY}/L=${LOCATION}/CN=${DOMAINS%%,*}" \
            -reqexts SAN \
            -config <(cat "${OPENSSL_CONF}" \
                <(printf "[SAN]\nsubjectAltName=%s" "$san_list")) \
            -out "${OUTDIR}/${name}.csr"

        # Sign certificate
        openssl x509 -req -days "$DAYS" \
            -in "${OUTDIR}/${name}.csr" \
            -CA "${OUTDIR}/ca.crt" \
            -CAkey "${OUTDIR}/ca.key" \
            -CAcreateserial \
            -extensions SAN \
            -extfile <(printf "[SAN]\nsubjectAltName=%s" "$san_list") \
            -out "${OUTDIR}/${name}.crt"

        rm -f "${OUTDIR}/${name}.csr"
    fi
    chmod 644 "${OUTDIR}/${name}.crt"
}

echo "Starting certificate generation..."
echo "Configuration:"
echo "  CA Domain: $CA_DOMAIN"
echo "  Service Domain List: $DOMAINS"
echo "  IP List: $IPS"
echo "  Output Directory: $OUTDIR"
echo "  Certificate Validity: $DAYS days"
echo "  Key Size: $KEY_SIZE bits"

# Generate CA certificate
generate_key "ca"
generate_cert "ca" true

# Generate server certificate
generate_key "server"
generate_cert "server"

# Generate client certificate
generate_key "client"
generate_cert "client"

echo "
Certificate generation completed! Files have been saved in the ${OUTDIR}/ directory
Permissions set:
  - Directory permissions: 700
  - Private key permissions: 600
  - Certificate permissions: 644"
