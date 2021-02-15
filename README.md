# JWT-library
An abstract JWT library for building, verifying and resolving JWTs using both JWS and JWE.

Algorithms supported for JWS
- RSASSA-PKCS1-v1_5 using SHA256
- RSASSA-PKCS1-v1_5 using SHA384
- RSASSA-PKCS1-v1_5 using SHA512
- HMAC using SHA-256
- HMAC using SHA-384
- HMAC using SHA-512

Algorithms supported for encrypting asymmetric keys in JWE
- RSA using Optimal Asymmetric Encryption Padding (OAEP)

Algorithms supported for payload encryption in JWE
- Advanced Encryption Standard (AES) using 128 bit keys in Galois/Counter Mode
- Advanced Encryption Standard (AES) using 256 bit keys in Galois/Counter Mode
