package main

import (
	// "fmt"
	"log"

	// "github.com/etiennebch/shamir-sss/shamir"
	"github.com/etiennebch/shamir-sss/galois"
)

func main() {
	field := galois.NewField256()
	log.Print(field.Divide(249, 8))
	// secret := []byte("secret")
	// shares := shamir.Split(secret, 3, 2)
	// log.Print(shares)
	// recv := shamir.Recover(shares[0:2])
	// log.Print(string(recv))
}
