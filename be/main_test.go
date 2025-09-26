package main

import (
	"fmt"
	"testing"
)

func TestAES256Decode(t *testing.T) {
	got, err := AES256Decode("U2FsdGVkX1/nhzuDGJgWQqnn42ycutivMp8Rc3O3WQw=", "2d328aba46aa98b7791265587db64b495388929834d99285e2d56a40c90ac1d6")
	fmt.Println(got, err)
}

func TestAES256Encode(t *testing.T) {
	key := "2d328aba46aa98b7791265587db64b495388929834d99285e2d56a40c90ac1d6"
	got, err := AES256Encode("test", key)
	fmt.Println(got, err)
	fmt.Println("Decode")
	fmt.Println("Decode")
	got, err = AES256Decode(got, key)
	fmt.Println(got, err)
}
