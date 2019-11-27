package main

import (
	"encoding/binary"
	"math/rand"

	cryptorand "crypto/rand"
)

// source represents a randomness source suitable for cryptographic use.
type source [8]byte

// Int63 implements the Source interface.
// It returns a non-negative random 63-bit integer.
func (s *source) Int63() int64 {
	// initialize the source with cryptography-suitable randomness
	cryptorand.Read(s[:])
	return int64(binary.BigEndian.Uint64(s[:]) & (1<<63 - 1))
}

// Seed implements the Source interface.
// It panics as we draw randomness using crypto/rand (see Int63) and is therefore of no use here.
func (s *source) Seed(seed int64) {
	panic("seed should not be used")
}

// PermSecure generates a permutation of the integer [0,n) from our cryptographically secure source of randomness.
// See https://stackoverflow.com/questions/40965044/using-crypto-rand-for-generating-permutations-with-rand-perm
func PermSecure(n int) []int {
	random := rand.New(new(source))
	return random.Perm(n)
}
