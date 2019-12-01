# shamir-sss
A Go implementation of Shamir Secret Sharing Scheme, to learn more about threshold cryptography.
**As I am not a crypto expert, this is not suitable for production use.**

I welcome any feedback on the implementation and security remarks (pull requests are the way to go),
as I am trying to validate the implemntation.

# how to use
All computation is done using AES Galois Finite Field 2^8, which means the secret cannot be split between more than 255 participants. A minimum threshold of 2 is required.

To run the demo if you have go already installed on your computer:
```bash
git clone https://github.com/etiennebch/shamir-sss
cd shamir-sss
go run main.go
```

To use as a dependency:
```bash
go get -u github.com/etiennebch/shamir-sss
```
```go
import shamir "github.com/etiennebch/shamir-sss"

func demo() {
    var secret := []byte("secret")
    var number, threshold uint8 = 5, 3
    shares := shamir.Split(secret, number, threshold)
    recover := shamir.Recover(shares)
}
```

# references
I used several references to implement the code. The hard part was writing code for computation in GF(2^8).
Hashicorp's Vault implementation notably helped me and pointed me to relevant references.

## Shamir algorithm
- https://cs.jhu.edu/~sdoshi/crypto/papers/shamirturing.pdf
- https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
- https://github.com/hashicorp/vault/blob/master/shamir/shamir.go
- https://github.com/WebOfTrustInfo/rwot8-barcelona/blob/master/draft-documents/shamir-secret-sharing-best-practices.md

## finite field computation
- https://www.samiam.org/galois.html

## others
- https://en.wikipedia.org/wiki/Lagrange_polynomial
- https://en.wikipedia.org/wiki/Horner%27s_method

# WIP
- add tests
- review for side channel attack vulnerabilities
- formal proof