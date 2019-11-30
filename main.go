package main

import (
	"encoding/hex"
	"github.com/etiennebch/shamir-sss/shamir"
	"log"
)

func main() {
	var number, threshold uint8 = 5, 3

	log.Print("using Shamir to split secret value: hello world")
	log.Printf("using number of shares: %d", number)
	log.Printf("using threshold: %d", threshold)

	shares := shamir.Split([]byte("hello world"), number, threshold)
	for i, share := range shares {
		log.Printf("share %d: %s", i+1, hex.EncodeToString(share))
	}

	// attempt recovery with less than threshold
	recv := shamir.Recover(shares[:threshold-1])
	log.Printf("attempted recovery with %d shares (threshold = %d): %s", threshold-1, threshold, string(recv))

	// attempt revovery with threshold
	recv = shamir.Recover(shares[:threshold])
	log.Printf("attempted recovery with %d shares (threshold = %d): %s", threshold, threshold, string(recv))
}
