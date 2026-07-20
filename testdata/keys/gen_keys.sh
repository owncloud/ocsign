#!/usr/bin/env bash
# gen_keys.sh — generate the committed test key/cert fixtures (spec §8).
#
# Produces, under testdata/keys/, a self-signed test intermediate CA and a leaf
# certificate (CN=example-app) with the constraints the verifier enforces
# (spec-core-verifier §4 step 2): basicConstraints CA:FALSE, keyUsage
# digitalSignature, extendedKeyUsage codeSigning. Both an EC P-384 set (primary)
# and an RSA-4096 set (fallback) are generated.
#
# These are TEST keys committed to the repo on purpose; they sign only fixtures.
# Re-run this only to regenerate fixtures (openssl is nondeterministic, so keys
# will differ). Requires OpenSSL 3.x.
set -euo pipefail

cd "$(dirname "$0")"

leaf_ext() {
	cat <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF
}

# $1 = prefix (ec|rsa); $2 = openssl genpkey algorithm args
gen_set() {
	local p="$1"
	shift

	# Intermediate CA key + self-signed cert. req -x509 takes its extensions via
	# -addext (OpenSSL 3.x); -extfile is an x509-command option only.
	openssl genpkey "$@" -out "${p}-intermediate.key"
	openssl req -x509 -new -key "${p}-intermediate.key" \
		-sha384 -days 3650 \
		-subj "/O=Example Org Test CA/CN=Example Test Intermediate" \
		-addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
		-addext "keyUsage=critical,keyCertSign,cRLSign" \
		-addext "subjectKeyIdentifier=hash" \
		-out "${p}-intermediate.crt"

	# Leaf key + CSR + cert signed by the intermediate.
	openssl genpkey "$@" -out "${p}-leaf.key"
	openssl req -new -key "${p}-leaf.key" \
		-subj "/CN=example-app" \
		-out "${p}-leaf.csr"
	openssl x509 -req -in "${p}-leaf.csr" \
		-CA "${p}-intermediate.crt" -CAkey "${p}-intermediate.key" \
		-CAcreateserial \
		-sha384 -days 825 \
		-extfile <(leaf_ext) \
		-out "${p}-leaf.crt"
	rm -f "${p}-leaf.csr" "${p}-intermediate.srl"
}

gen_set ec -algorithm EC -pkeyopt ec_paramgen_curve:P-384
gen_set rsa -algorithm RSA -pkeyopt rsa_keygen_bits:4096

# Core-identity leaf certs (CN=core) for --core signing tests. These reuse the
# existing leaf KEYS and intermediates, so no new private keys are introduced;
# ${p}-leaf.key pairs with both ${p}-leaf.crt (CN=example-app) and
# ${p}-core-leaf.crt (CN=core).
# $1 = prefix (ec|rsa)
gen_core_leaf() {
	local p="$1"
	openssl req -new -key "${p}-leaf.key" \
		-subj "/CN=core" \
		-out "${p}-core.csr"
	openssl x509 -req -in "${p}-core.csr" \
		-CA "${p}-intermediate.crt" -CAkey "${p}-intermediate.key" \
		-CAcreateserial \
		-sha384 -days 825 \
		-extfile <(leaf_ext) \
		-out "${p}-core-leaf.crt"
	rm -f "${p}-core.csr" "${p}-intermediate.srl"
}

gen_core_leaf ec
gen_core_leaf rsa

# Also emit the EC leaf key in SEC1 form (-----BEGIN EC PRIVATE KEY-----) so the
# loader's SEC1 path (spec §9) is exercised against a real OpenSSL artifact. The
# PKCS#8 ec-leaf.key and this SEC1 ec-leaf.sec1.key hold the same private key.
openssl ec -in ec-leaf.key -out ec-leaf.sec1.key 2>/dev/null

echo "generated EC and RSA test key/cert fixtures in $(pwd)"
