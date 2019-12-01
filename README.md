# shamir-sss
A Go implementation of Shamir Secret Sharing Scheme, to learn more about threshold cryptogrphy.
**As I am not a crypto expert, this is not suitable for production use.**

I welcome any feedback on the implementation and security remarks (pull requests are the way to go).

# technical considerations
All computation is done using AES Galois Finite Field 2^8.

# references
I used several references to implement the code. The hard part was writing code for computation in GF(2^8).
Hashicorp's Vault implementation notably helped me and pointed me to relevant references.

## Shamir algorithm
- https://cs.jhu.edu/~sdoshi/crypto/papers/shamirturing.pdf
- https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
- https://github.com/hashicorp/vault/blob/master/shamir/shamir.go
- https://github.com/WebOfTrustInfo/rwot8-barcelona/blob/master/draft-documents/shamir-secret-sharing-best-practices.md

## Finite field computation
- https://www.samiam.org/galois.html