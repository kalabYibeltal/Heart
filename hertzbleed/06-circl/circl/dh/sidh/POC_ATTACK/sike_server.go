package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/cloudflare/circl/dh/sidh"
	"github.com/cloudflare/circl/dh/sidh/internal/common"
)

type sikeVec struct {
	id      uint8
	name    string
	kem     *sidh.KEM
	KatFile string
	PkB     string
	PrB     string
}

func main() {

	var v sikeVec
	v.id = 1
	v.kem = sidh.NewSike751(rand.Reader)
	sk := sidh.NewPrivateKey(v.id, sidh.KeyVariantSike)
	pk := sidh.NewPublicKey(v.id, sidh.KeyVariantSike)
	sk.Generate(rand.Reader)

	sk.GeneratePublicKey(pk)
	fmt.Println("public keys!")
	pk.Print_PublicKey()

	var ssBsz = v.kem.SharedSecretSize()

	SHUT := []byte{'S', 'H', 'U', 'T'}
	SECRET := []byte{'S', 'E', 'C', 'R', 'E', 'T'}

	// handle `/` route
	http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		v_local := v
		v_local.kem = sidh.NewSike751(rand.Reader)
		var ssD [common.MaxSharedSecretBsz]byte
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			log.Printf("Error reading body: %v", err)
			http.Error(res, "can't read body", http.StatusBadRequest)
			return
		}

		ct := body

		if bytes.Compare(ct, SHUT) == 0 {
			fmt.Println("sk Scalar%v", sk.Scalar)
			for i := uint(0); i < 378; i++ {
				bit := (sk.Scalar[i>>3] >> (i & 7) & 1)
				fmt.Printf("%v\n", bit)
			}
			os.Exit(3)
		}

		if bytes.Compare(ct, SECRET) == 0 {
			fmt.Println("sk Scalar%v", sk.Scalar)
			for i := uint(0); i < 378; i++ {
				bit := (sk.Scalar[i>>3] >> (i & 7) & 1)
				fmt.Printf("%v\n", bit)
			}
		} else {
			v_local.kem.Reset()
			v_local.kem.Decapsulate(ssD[:ssBsz], sk, pk, ct)
			fmt.Fprint(res, "SIKE!")
		}
	})

	// Run server on port "9000"
	log.Fatal(http.ListenAndServe(":9000", nil))

}
