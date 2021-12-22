package util

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	types "github.com/iEvan-lhr/acrossCloud/type"
	"hash"
	"io"
	rand2 "math/rand"
	"net/http"
	"sort"
	"strings"
)

const numBytes = "1234567890"

var filterKey = []string{"x-ca-signature", "x-ca-signature-headers", "accept", "content-md5", "content-type", "user-agent", "date", "host", "token"}

type UUID [16]byte

func getUUID() (uuidHex string) {
	uuid := newUUID()
	uuidHex = hex.EncodeToString(uuid[:])
	return
}

func newUUID() UUID {
	ns := UUID{}
	safeRandom(ns[:])
	u := newFromHash(md5.New(), ns, randStringBytes(16))
	u[6] = (u[6] & 0x0f) | (byte(2) << 4)
	u[8] = u[8]&(0xff>>2) | (0x02 << 6)

	return u
}
func safeRandom(dest []byte) {
	if _, err := rand.Read(dest); err != nil {
		panic(err)
	}
}

func newFromHash(h hash.Hash, ns UUID, name string) UUID {
	u := UUID{}
	h.Write(ns[:])
	h.Write([]byte(name))
	copy(u[:], h.Sum(nil))

	return u
}
func randStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = numBytes[rand2.Intn(len(numBytes))]
	}
	return string(b)
}
func GetNonce() string {
	return getUUID()
}

func GetContentMD5(body string) string {
	sum := md5.Sum([]byte(body))
	b64 := base64.StdEncoding.EncodeToString(sum[:])
	return b64
}
func GetSignatureV1(request *types.Request, signedParams map[string]string, secret string) string {
	return getSignature(secret, signedParams, request)
}

func getSignature(appSecret string, signedParams map[string]string, req *types.Request) string {
	signedHeader := getSignedHeader(req)
	url := buildUrl(req.Pathname, signedParams)
	date := req.Headers["date"]
	accept := req.Headers["accept"]
	contentType := req.Headers["content-type"]
	contentMd5 := req.Headers["content-md5"]
	signStr := req.Method + "\n" + accept + "\n" + contentMd5 + "\n" + contentType + "\n" + date + "\n" + signedHeader + "\n" + url
	h := hmac.New(func() hash.Hash { return sha256.New() }, []byte(appSecret))
	_, err := io.WriteString(h, signStr)
	if err != nil {
		return ""
	}
	signedStr := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return signedStr
}

// Sorter defines the key-value structure for storing the sorted data in signHeader.
type Sorter struct {
	Keys   []string
	Values []string
}

func buildUrl(pathName string, signedParams map[string]string) string {
	url := pathName
	hs := newSorter(signedParams)
	hs.Sort()
	if len(hs.Keys) > 0 {
		url += "?"
	}
	for key, value := range hs.Keys {
		if !strings.HasSuffix(url, "?") {
			url += "&"
		}
		url += value + "=" + hs.Values[key]
	}

	return url
}

// newSorter is an additional function for function Sign.
func newSorter(m map[string]string) *Sorter {
	hs := &Sorter{
		Keys:   make([]string, 0, len(m)),
		Values: make([]string, 0, len(m)),
	}

	for k, v := range m {
		hs.Keys = append(hs.Keys, k)
		hs.Values = append(hs.Values, v)
	}
	return hs
}

// Sort is an additional function for function SignHeader.
func (hs *Sorter) Sort() {
	sort.Sort(hs)
}

// Len is an additional function for function SignHeader.
func (hs *Sorter) Len() int {
	return len(hs.Values)
}

// Less is an additional function for function SignHeader.
func (hs *Sorter) Less(i, j int) bool {
	return bytes.Compare([]byte(hs.Keys[i]), []byte(hs.Keys[j])) < 0
}

// Swap is an additional function for function SignHeader.
func (hs *Sorter) Swap(i, j int) {
	hs.Values[i], hs.Values[j] = hs.Values[j], hs.Values[i]
	hs.Keys[i], hs.Keys[j] = hs.Keys[j], hs.Keys[i]
}

func getSignedHeader(request *types.Request) string {
	signedHeader := ""
	signedHeaderKeys := ""
	hs := newSorter(request.Headers)
	hs.Sort()
	for key, value := range hs.Keys {
		if !isFilterKey(value) {
			signedHeaderKeys += value + ","
			signedHeader += value + ":" + hs.Values[key] + "\n"
		}
	}
	request.Headers["x-ca-signature-headers"] = strings.TrimSuffix(signedHeaderKeys, ",")
	return strings.TrimSuffix(signedHeader, "\n")
}

func isFilterKey(key string) bool {
	for _, value := range filterKey {
		if key == value {
			return true
		}
	}
	return false
}
func Retryable(err error) bool {
	if err == nil {
		return false
	}
	if realErr, ok := err.(*types.SDKError); ok {
		if realErr.StatusCode == 0 {
			return false
		}
		code := realErr.StatusCode
		return code >= http.StatusInternalServerError
	}
	return true
}
func IsFail(code int) bool {
	return code < 200 || code >= 300
}
