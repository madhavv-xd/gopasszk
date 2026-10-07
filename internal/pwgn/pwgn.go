// password generation internal
package pwgn

import (
	"crypto/rand"
	"errors"
	"math/big"
)

const charset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
	"0123456789" +
	"!@#$%^&*()-_=+[]{}?"

func Generate(length int) (string , error ){
	if length < 8 {
		return "" ,errors.New("pass length must be atleast 8")
	}

	max := big.NewInt(int64(len(charset)))
	out := make([]byte , length)

	for i := range out {
		n,err := rand.Int(rand.Reader , max)
		if err != nil {
			return "" , err 
		}
		out[i] = charset[n.Int64()]
	}
	return string(out) , nil 
}