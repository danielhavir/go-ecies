/*
	utils.go

	Utility script for reading, writing files and hex encoding/decoding

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

	utils.go Daniel Havir, 2018
*/

package main

import (
	"encoding/hex"
	"io/ioutil"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func readfile(path string) []byte {
	dat, err := ioutil.ReadFile(path)
	check(err)
	return dat
}

func writefile(text []byte, path string) {
	err := ioutil.WriteFile(path, text, 0664)
	check(err)
}

func decodehex(src []byte) []byte {
	dst := make([]byte, hex.DecodedLen(len(src)))
	hex.Decode(dst, src)
	return dst
}

func encodehex(src []byte) []byte {
	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)
	return dst
}

func readhexfile(path string) []byte {
	src := readfile(path)
	dst := decodehex(src)
	return dst
}

func writehexfile(src []byte, path string) {
	text := encodehex(src)
	writefile(text, path)
}
