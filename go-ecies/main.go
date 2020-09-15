/*
	run.go

	Main function for the ECIES CLI interface.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
	"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
	LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
	A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
	OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
	SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
	LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
	DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
	THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
	OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

	run.go Daniel Havir, 2018
*/

package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"fmt"
	"math/big"

	"github.com/udhos/go-ecies/ecies"
)

func main() {
	encrypt := flag.Bool("en", false, "Encrypt")
	decrypt := flag.Bool("de", false, "Decrypt")
	genKey := flag.Bool("generate-key-pair", false, "Generate private-public key pair")
	inputPath := flag.String("in", "file.txt", "Path to input file.")
	outputPath := flag.String("out", "out.out", "Path to output file.")
	privatePath := flag.String("prv", "key.pem", "Path to private key.")
	publicPath := flag.String("pub", "key.pub", "Path to public key.")
	mode := flag.String("mode", "P256", "Mode defines whether to use P256-AES128-SHA256 (\"P256\") or P521-AES256-SHA512 (\"P521\").")
	useHex := flag.Bool("hex", false, "Encode to/from hex.")
	flag.Parse()

	if !(*mode == "P256" || *mode == "P521") {
		fmt.Println("Mode must be either \"P256\" or \"P521\".")
		return
	}

	var private ecies.PrivateKey
	var public ecies.PublicKey
	var curve elliptic.Curve
	reader := rand.Reader
	if *mode == "P521" {
		curve = elliptic.P521()
	} else if *mode == "P256" {
		curve = elliptic.P256()
	}

	if *genKey {
		private = *ecies.GenerateKey(reader, curve)
		public = private.PublicKey
		writehexfile(private.D.Bytes(), *privatePath)
		writehexfile(elliptic.Marshal(curve, public.X, public.Y), *publicPath)
		fmt.Printf("Key successfully generated into %s and %s\n", *privatePath, *publicPath)
	} else {
		if *encrypt {
			X, Y := elliptic.Unmarshal(curve, readhexfile(*publicPath))
			public = ecies.PublicKey{X: X, Y: Y, Curve: curve}
		} else if *decrypt {
			public.Curve = curve
			private = ecies.PrivateKey{PublicKey: public,
				D: new(big.Int).SetBytes(readhexfile(*privatePath))}
		}
	}

	if !(*encrypt || *decrypt) {
		fmt.Println("Did you forget to specify encrypt \"-en\" or decrypt \"-de\"?")
		return
	}

	var intext []byte

	if *encrypt {
		intext = readfile(*inputPath)
		outtext := ecies.Encrypt(reader, &public, intext, nil, nil)
		if *useHex {
			writehexfile(outtext, *outputPath)
		} else {
			writefile(outtext, *outputPath)
		}
	} else if *decrypt {
		if *useHex {
			intext = readhexfile(*inputPath)
		} else {
			intext = readfile(*inputPath)
		}
		outtext := ecies.Decrypt(&private, intext, nil, nil)
		writefile(outtext, *outputPath)
	}
}
