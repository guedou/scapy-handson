# Fun With X.509 Certificates

Scapy is able to natively parse ASN.1. Internally, this feature is used for SNMP
as well as X.509 certificate parsing.

This trophy shows you some cool things that you can do!

## Tasks

### Task #1

- load the `tls` layer with `load_layer()`
- retrieve the `grehack.fr` X.509 certificate as DER
- use `der2pem()` to convert the certificate to PEM
- write the PEM file to a new file, and check the result with `openssl x509`
- parse the certificate content with the `X509_Cert()` class
- display the signature algorithm, and the subject name
- find the name of the OCSP server from the extensions

### Task #2

- use the `Cert()` object to load the certificate from its filename
- display the number of days until expiration
- is it a self-signed certificate?

### Task #3

- generate an RSA private key using `openssl genrsa`
- load it in Scapy with `PrivKey()`
- assign your birthday to the certificate serial number
- use the `resignCert()` method to sign the certificate with your own signature
- check the result with `openssl x509`
- verify the signature using the `PrivKey` `verifyCert()` method

## Hints

- X.509 certificate can be downloaded from a web browser status bar or developer tools
- use the `obj` argument of `der2pem()` with the 'CERTIFICATE' type
