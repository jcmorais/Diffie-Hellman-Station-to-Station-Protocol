# Diffie-Hellman-Station-to-Station-Protocol
In public-key cryptography, the Station-to-Station (STS) protocol is a cryptographic key agreement scheme based on classic Diffie–Hellman that provides mutual key and entity authentication.  In addition to protecting the established key from an attacker, the STS protocol uses no timestamps and provides perfect forward secrecy. It also entails two-way explicit key confirmation, making it an authenticated key agreement with key confirmation (AKC) protocol.

Supposing all setup data has been shared, the STS protocol proceeds as follows. If a step cannot be completed, the protocol immediately stops. All exponentials are in the group specified by p.

1. Alice generates a random number x and computes and sends the exponential gx to Bob.
2. Bob generates a random number y and computes the exponential gy.
3. Bob computes the shared secret key K = (gx)y.
4. Bob concatenates the exponentials (gy, gx) (order is important), signs them using his asymmetric (secret) key B, and then encrypts the signature with K. He sends the ciphertext along with his own exponential gy to Alice.
5. Alice computes the shared secret key K = (gy)x.
6. Alice decrypts and verifies Bob's signature using his asymmetric public key.
7. Alice concatenates the exponentials (gx, gy) (order is important), signs them using her asymmetric (secret) key A, and then encrypts the signature with K. She sends the ciphertext to Bob.
Bob decrypts and verifies Alice's signature using her asymmetric public key.
8. Alice and Bob are now mutually authenticated and have a shared secret. This secret, K, can then be used to encrypt further communication. The basic form of the protocol is formalized in the following three steps:

(1) Alice → Bob : g^x

(2) Alice ← Bob : g^y, EK(SB(g^y, g^x))

(3) Alice → Bob : Ek(SA(g^x, g^y))
