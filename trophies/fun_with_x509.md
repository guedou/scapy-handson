# Fun with X.509 certificates

Scapy is able to natively parse ASN.1. Internally, this feature is used for SNMP
as well as X.509 certificate parsing.

This trophy shows you some cool things that you can do.

## Tasks

**task #1**

- retrieve `grehack.fr` X.509 certificate as DER
- use `der2pem()` to convert the certificate to PEM
- check the result with `openssl x509`
- parse its content with the `X509_Cert` class
- display the signature algorithm, and the subject name
- find the name of the OCSP server

**task #2**

- use the `Cert` object to load the certificate from its filename
- display the number of days until expiration
- is it a self signed certificate ?

**task #3**

- generate an RSA private key using `openssl rsa`
- load it in Scapy with `PrivKey`
- assign your birthday to the certificate serial number
- use the `resignCert` method to sign the certificate with your own signature
- check the result with `openssl x509`
- verify the signature using the `PrivKey` `verify` method

## Hints

- X.509 certificate can be downloaded from a web browser status bar
- use the `obj` argument of `der2pem()` with the 'CERTIFICATE' type
- set the `verify()` `h` and `t` arguments to sha256 and pkcs
