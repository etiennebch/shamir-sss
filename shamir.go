package main

import "crypto/rand"

// Split splits a secret of arbitrary length into n shares using Shamir secret sharing scheme, such
// that at least k <= n shares (known as the threshold) must be combined in order to recover the secret.
// We refer to such a scheme as a (k,n) Shamir scheme.
//
// All computation is done in the Galois finite field 2^8 - GF(2^8) - as it is convenient for byte-oriented
// computation, and is the de-facto field used by the AES cipher.
// The maximum number of shares that can be dealt is the 2^8-1.
//
// The secret is processed one byte at a time. This means that every byte of the secret of length p is split using
// Shamir's scheme. In a (k,n) Shamir scheme, it yields n "mini-shares" for every byte of the secret.
// Thus, every participant in the scheme receives a share, which is a collection of the p mini-shares attributed
// to him. This enables processing arbitrary length secrets.
//
// In addition to the value of the shares themselves, we need to keep track of the point to evaluate the polynomials
// used to split every byte of the secret. This point is one byte long since we operate in GF(2^8).
// Assuming that for a given participant, we use the same point across all the mini-shares, the total length of a
// share is therefore p + 1.
// Using the same point across mini-shares does not reduce security so long as we still use distinct points for distinct participants.
//
// Note that Shamir secret sharing scheme is secure in that with less than k shares, no adversary can
// learn anything about the secret. However, Shamir's scheme does leak the size of the secret
// since the length of the share is p + 1, unless the secret is padded somehow.
// Padding the secret would still leak the information that the secret is at most the length of the
// padded secret + 1.
//
// For large secrets, a common approach is to first encrypt the secret using a strong cipher, and to
// use Shamir secret sharing on the decryption key rather than on the underlying secret.
//
// The algorithm used is as follows:
// For every byte of the secret of length p, we chose a random polynomial with coefficients in GF(2^8), and set
// the polynomial's intercept to the value of the byte being processed.
// Then, we pick n distinct points from GF(2^8) such that each share's recipient will be assigned a
// unique point that we denote x[i], 0 <= i <= n <= 255.
// Then, for each byte of the secret, we evaluate its associated polynomial for all x[i] and the value
// of the polynomial at that point is the mini-share for recipient i.
// We return a 2D byte array containing the mini-shares + x[i] for recipient i.
// Recipient i would receive the byte array [y[0], y[1], ... y[p-1], x[i]].
func Split(secret []byte, n, threshold uint8) ([][]byte, error) {
	if threshold > n {
		// TODO: error
	}
	if len(secret) == 0 {
		// TODO: error
	}

	// allocate a 2D array that will hold the shares of the n recipients
	shares := make([][]byte, n, n)
	// allocate each recipient's shares array.
	for i := range shares {
		shares[i] = make([]byte, len(secret)+1, len(secret)+1)
	}
	x := pickCoordinates(n)

	for idx, chunk := range secret {
		polynomial, err := randomPolynomialWithIntercept(chunk, threshold)
		if err != nil {
			// TODO: timing side-channel attack possible ?
		}
		// compute the value of the polynomial for every coordinate x[i]
		for i := 0; uint8(i) < n; i++ {
			share := polynomialValue(x[i], polynomial)
			shares[i][idx] = share
		}
	}
	// TODO: add x[i] to results
	return shares, nil
}

func Recover() {}

// randomPolynomialWithIntercept choses order-1 random coefficients in GF(2^8) and sets the polynomial
// intercept according to the value passed in.
// In the context of a (k,n) Shamir scheme, the polynomial order must be 0 <= k <= n. As we use GF(2^8),
// the polynomial order is between 0 and 255.
// The returned value is a byte array b of length k such that b[0] = intercept.
func randomPolynomialWithIntercept(intercept byte, order uint8) ([]byte, error) {
	coefficients := make([]byte, order)
	_, err := rand.Read(coefficients)
	if err != nil {
		return nil, err
	}
	// override the first slot with the intercept
	coefficients[0] = intercept
	return coefficients, nil
}

func pickCoordinates(n uint8) []byte {
	return nil
}

func polynomialValue(x byte, polynomial []byte) byte {
	return 0
}