package main

// Split splits a secret of arbitrary length into n shares using Shamir secret sharing scheme, such
// that at least k <= n shares (known as the threshold) must be combined in order to recover the secret.
//
// All computation is done in the Galois finite field 2^8 - GF(2^8) - as it is convenient for byte-oriented
// computation, and is the de-facto field used by the AES cipher.
// The maximum number of shares that can be dealt is the 2^8-1.
//
// The secret is processed one byte at a time. Therefore, a share is really an array of bytes which
// contains a share for every byte-size chunk of the secret. This allows for arbitrary length secrets.
//
// In addition to the value of the shares, we need to keep track of the point used to evaluate the polynomials
// of every byte-size share of the secret, which is also one byte long since we operate in GF(2^8).
// Thus, the total length of the output returned to the caller is len(secret) + 1
//
// Note that Shamir secret sharing scheme is secure in that with less than k shares, no adversary can
// learn anything about the secret. However, Shamir's scheme does leak the size of the secret
// since the length of the share is the secret length + 1, unless the secret is padded somehow.
// Padding the secret would still leak the information that the secret is at most the length of the
// padded secret + 1.
//
// For large secrets, a common approach is to first encrypt the secret using a strong cipher, and to
// use Shamir secret sharing on the decryption key rather than on the underlying secret.
//
// The algorithm used is as follows:
// For every byte of the secret, we chose a random polynomial with coefficients in GF(2^8), and set
// the polynomial's intercept to the chunk of the secret being processed.
// Then, we pick n distinct points from GF(2^8) such that each share's recipient will be assigned a
// unique point that we denote x[i], 0 <= i <= n <= 255.
// Then, for each byte of the secret, we evaluate its associated polynomial for all x[i] and the value
// of the polynomial at that point is the share for this byte of the secret, for recipient i.
// We return a 2D byte array containing the shares for every recipient + x[i].
// Recipient i would receive the byte array [y[0], y[1], ... y[len(secret)], x[i]].
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
		polynomial := randomPolynomialWithIntercept(chunk)
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

func randomPolynomialWithIntercept(intercept byte) []byte {
	return nil
}

func pickCoordinates(n uint8) []byte {
	return nil
}

func polynomialValue(x byte, polynomial []byte) byte {
	return 0
}
