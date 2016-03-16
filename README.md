
# Diffie-Hellman-Station-to-Station-Protocol
In public-key cryptography, the Station-to-Station (STS) protocol is a cryptographic key agreement scheme based on classic Diffie–Hellman that provides mutual key and entity authentication.  In addition to protecting the established key from an attacker, the STS protocol uses no timestamps and provides perfect forward secrecy. It also entails two-way explicit key confirmation, making it an authenticated key agreement with key confirmation (AKC) protocol.

Supposing all setup data has been shared, the STS protocol proceeds as follows. If a step cannot be completed, the protocol immediately stops.

1. Server generates a random number x and computes and sends the exponential g^x to Client.
2. Client generates a random number y and computes the exponential g^y.
3. Client computes the shared secret key K = (g^x)^y.
4. Client concatenates the exponentials (gy, gx), signs them using his asymmetric (secret) key B, and then encrypts the signature with K. He sends the ciphertext along with his own exponential gy to Server.
5. Server computes the shared secret key K = (g^y)^x.
6. Server decrypts and verifies Client's signature using his asymmetric public key.
7. Server concatenates the exponentials (g^x, g^y) (order is important), signs them using her asymmetric (secret) key A, and then encrypts the signature with K. She sends the ciphertext to Client.
Client decrypts and verifies Server's signature using her asymmetric public key.
8. Server and Client are now mutually authenticated and have a shared secret. This secret, K, can then be used to encrypt further communication. 


The basic form of the protocol is formalized in the following three steps:

Server → Client : p, g, g^(x)

Server ← Client : g^(y)

Server, Client : Key = g^(xy)

Server ← Client : Ek(S(g^(y), g^(x)))

Server → Client : Ek(S(g^(x), g^(y)))


https://en.wikipedia.org/wiki/Station-to-Station_protocol
