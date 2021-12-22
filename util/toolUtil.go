package util

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	types "github.com/alibabacloud-go/acrossCloud/type"
	"golang.org/x/net/proxy"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var clientPool = &sync.Map{}

var loggerParam = []string{"{time}", "{start_time}", "{ts}", "{channel}", "{pid}", "{host}", "{method}", "{uri}", "{version}", "{target}", "{hostname}", "{code}", "{error}", "{req_headers}", "{res_body}", "{res_headers}", "{cost}"}

var validateParams = []string{"require", "pattern", "maxLength", "minLength", "maximum", "minimum", "maxItems", "minItems"}

var basicTypes = []string{
	"int", "int16", "int64", "int32", "float32", "float64", "string", "bool", "uint64", "uint32", "uint16",
}
var debugLog = types.Init("toolUtil")

var evanDo = func(fn func(req *http.Request) (*http.Response, error)) func(req *http.Request) (*http.Response, error) {
	return fn
}

const (
	// TransferStartedEvent transfer started, set TotalBytes
	TransferStartedEvent types.ProgressEventType = 1 + iota
	// TransferDataEvent transfer data, set ConsumedBytes and TotalBytes
	TransferDataEvent
	// TransferCompletedEvent transfer completed
	TransferCompletedEvent
	// TransferFailedEvent transfer encounters an error
	TransferFailedEvent
)

func DefaultNumber(reaNum, defaultNum int) int {
	if reaNum == 0 {
		return defaultNum
	}
	return reaNum
}
func DefaultString(reaStr, defaultStr string) string {
	if reaStr == "" {
		return defaultStr
	}
	return reaStr
}

func validate(dataValue reflect.Value) error {
	if strings.HasPrefix(dataValue.Type().String(), "*") { // Determines whether the input is a structure object or a pointer object
		if dataValue.IsNil() {
			return nil
		}
		dataValue = dataValue.Elem()
	}
	dataType := dataValue.Type()
	for i := 0; i < dataType.NumField(); i++ {
		field := dataType.Field(i)
		valueField := dataValue.Field(i)
		for _, value := range validateParams {
			err := validateParam(field, valueField, value)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
func validateParam(field reflect.StructField, valueField reflect.Value, tagName string) error {
	tag, containsTag := field.Tag.Lookup(tagName) // Take out the checked regular expression
	if containsTag && tagName == "require" {
		err := checkRequire(field, valueField)
		if err != nil {
			return err
		}
	}
	if strings.HasPrefix(field.Type.String(), "[]") { // Verify the parameters of the array type
		err := validateSlice(field, valueField, containsTag, tag, tagName)
		if err != nil {
			return err
		}
	} else if valueField.Kind() == reflect.Ptr { // Determines whether it is a pointer object
		err := validatePtr(field, valueField, containsTag, tag, tagName)
		if err != nil {
			return err
		}
	}
	return nil
}
func checkRequire(field reflect.StructField, valueField reflect.Value) error {
	name, _ := field.Tag.Lookup("json")
	str := strings.Split(name, ",")
	name = str[0]
	if !valueField.IsNil() && valueField.IsValid() {
		return nil
	}
	return errors.New(name + " should be set ")
}

func validateSlice(field reflect.StructField, valueField reflect.Value, containsRegexpTag bool, tag, tagName string) error {
	if valueField.IsValid() && !valueField.IsNil() { // Determines whether the parameter has a value
		if containsRegexpTag {
			if tagName == "maxItems" {
				err := checkMaxItems(field, valueField, tag)
				if err != nil {
					return err
				}
			}

			if tagName == "minItems" {
				err := checkMinItems(field, valueField, tag)
				if err != nil {
					return err
				}
			}
		}

		for m := 0; m < valueField.Len(); m++ {
			elementValue := valueField.Index(m)
			if elementValue.Type().Kind() == reflect.Ptr { // Determines whether the child elements of an array are of a basic type
				err := validatePtr(field, elementValue, containsRegexpTag, tag, tagName)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func checkMinimum(field reflect.StructField, valueField reflect.Value, tag string) error {
	if valueField.IsValid() && valueField.String() != "" {
		minimum, err := strconv.ParseFloat(tag, 64)
		if err != nil {
			return err
		}

		byt, _ := json.Marshal(valueField.Interface())
		num, err := strconv.ParseFloat(string(byt), 64)
		if err != nil {
			return err
		}
		if minimum > num {
			errMsg := fmt.Sprintf("The size of %s is %f which is less than %f", field.Name, num, minimum)
			return errors.New(errMsg)
		}
	}
	return nil
}
func validatePtr(field reflect.StructField, elementValue reflect.Value, containsRegexpTag bool, tag, tagName string) error {
	if elementValue.IsNil() {
		return nil
	}
	if isFilterType(elementValue.Elem().Type().String(), basicTypes) {
		if containsRegexpTag {
			if tagName == "pattern" {
				err := checkPattern(elementValue.Elem(), tag)
				if err != nil {
					return err
				}
			}

			if tagName == "maxLength" {
				err := checkMaxLength(field, elementValue.Elem(), tag)
				if err != nil {
					return err
				}
			}

			if tagName == "minLength" {
				err := checkMinLength(field, elementValue.Elem(), tag)
				if err != nil {
					return err
				}
			}

			if tagName == "maximum" {
				err := checkMaximum(field, elementValue.Elem(), tag)
				if err != nil {
					return err
				}
			}

			if tagName == "minimum" {
				err := checkMinimum(field, elementValue.Elem(), tag)
				if err != nil {
					return err
				}
			}
		}
	} else {
		err := validate(elementValue)
		if err != nil {
			return err
		}
	}
	return nil
}

func checkPattern(valueField reflect.Value, tag string) error {
	if valueField.IsValid() && valueField.String() != "" {
		value := valueField.String()
		r, _ := regexp.Compile("^" + tag + "$")
		if match := r.MatchString(value); !match { // Determines whether the parameter value satisfies the regular expression or not, and throws an error
			return errors.New(value + " is not matched " + tag)
		}
	}
	return nil
}
func checkMaxLength(field reflect.StructField, valueField reflect.Value, tag string) error {
	if valueField.IsValid() && valueField.String() != "" {
		maxLength, err := strconv.Atoi(tag)
		if err != nil {
			return err
		}
		length := valueField.Len()
		if valueField.Kind().String() == "string" {
			length = strings.Count(valueField.String(), "") - 1
		}
		if maxLength < length {
			errMsg := fmt.Sprintf("The length of %s is %d which is more than %d", field.Name, length, maxLength)
			return errors.New(errMsg)
		}
	}
	return nil
}
func checkMinLength(field reflect.StructField, valueField reflect.Value, tag string) error {
	if valueField.IsValid() {
		minLength, err := strconv.Atoi(tag)
		if err != nil {
			return err
		}
		length := valueField.Len()
		if valueField.Kind().String() == "string" {
			length = strings.Count(valueField.String(), "") - 1
		}
		if minLength > length {
			errMsg := fmt.Sprintf("The length of %s is %d which is less than %d", field.Name, length, minLength)
			return errors.New(errMsg)
		}
	}
	return nil
}
func checkMaximum(field reflect.StructField, valueField reflect.Value, tag string) error {
	if valueField.IsValid() && valueField.String() != "" {
		maximum, err := strconv.ParseFloat(tag, 64)
		if err != nil {
			return err
		}
		byt, _ := json.Marshal(valueField.Interface())
		num, err := strconv.ParseFloat(string(byt), 64)
		if err != nil {
			return err
		}
		if maximum < num {
			errMsg := fmt.Sprintf("The size of %s is %f which is greater than %f", field.Name, num, maximum)
			return errors.New(errMsg)
		}
	}
	return nil
}

func isFilterType(realType string, filterTypes []string) bool {
	for _, value := range filterTypes {
		if value == realType {
			return true
		}
	}
	return false
}
func checkMaxItems(field reflect.StructField, valueField reflect.Value, tag string) error {
	if valueField.IsValid() && valueField.String() != "" {
		maxItems, err := strconv.Atoi(tag)
		if err != nil {
			return err
		}
		length := valueField.Len()
		if maxItems < length {
			errMsg := fmt.Sprintf("The length of %s is %d which is more than %d", field.Name, length, maxItems)
			return errors.New(errMsg)
		}
	}
	return nil
}
func checkMinItems(field reflect.StructField, valueField reflect.Value, tag string) error {
	if valueField.IsValid() {
		minItems, err := strconv.Atoi(tag)
		if err != nil {
			return err
		}
		length := valueField.Len()
		if minItems > length {
			errMsg := fmt.Sprintf("The length of %s is %d which is less than %d", field.Name, length, minItems)
			return errors.New(errMsg)
		}
	}
	return nil
}

func AllowRetry(retry interface{}, retryTimes int) bool {
	if retryTimes == 0 {
		return true
	}
	retryMap, ok := retry.(map[string]interface{})
	if !ok {
		return false
	}
	retryable, ok := retryMap["retryable"].(bool)
	if !ok || !retryable {
		return false
	}

	maxAttempts, ok := retryMap["maxAttempts"].(int)
	if !ok || maxAttempts < retryTimes {
		return false
	}
	return true
}
func GetBackoffTime(backoff interface{}, retryTimes int) int {
	backoffMap, ok := backoff.(map[string]interface{})
	if !ok {
		return 0
	}
	policy, ok := backoffMap["policy"].(string)
	if !ok || policy == "no" {
		return 0
	}

	period, ok := backoffMap["period"].(int)
	if !ok || period == 0 {
		return 0
	}

	maxTime := math.Pow(2.0, float64(retryTimes))
	return rand.Intn(int(maxTime-1)) * period
}

func Sleep(backoffTime int) {
	sleepTime := time.Duration(backoffTime) * time.Second
	time.Sleep(sleepTime)
}

// NewRequest is used shortly create Request
func NewRequest() (req *types.Request) {
	return &types.Request{
		Headers: map[string]string{},
		Query:   map[string]string{},
	}
}

// NewResponse is create response with http response
func NewResponse(httpResponse *http.Response) (res *types.Response) {
	res = &types.Response{}
	res.Body = httpResponse.Body
	res.Headers = make(map[string]string)
	res.StatusCode = httpResponse.StatusCode
	res.StatusMessage = httpResponse.Status
	return
}

func Merge(args ...interface{}) map[string]string {
	finalArg := make(map[string]string)
	for _, obj := range args {
		switch obj.(type) {
		case map[string]*string:
			arg := obj.(map[string]string)
			for key, value := range arg {
				if value != "" {
					finalArg[key] = value
				}
			}
		default:
			byt, _ := json.Marshal(obj)
			arg := make(map[string]string)
			err := json.Unmarshal(byt, &arg)
			if err != nil {
				return finalArg
			}
			for key, value := range arg {
				if value != "" {
					finalArg[key] = value
				}
			}
		}
	}
	return finalArg
}
func InitLogMsg(fieldMap map[string]string) {
	for _, value := range loggerParam {
		fieldMap[value] = ""
	}
}
func DoRequest(request *types.Request, requestRuntime map[string]interface{}) (response *types.Response, err error) {
	runtimeObject := NewRuntimeObject(requestRuntime)
	fieldMap := make(map[string]string)
	InitLogMsg(fieldMap)
	defer func() {
		if runtimeObject.Logger != nil {
			runtimeObject.Logger.PrintLog(fieldMap, err)
		}
	}()
	if request.Method == "" {
		request.Method = "GET"
	}

	if request.Protocol == "" {
		request.Protocol = "http"
	} else {
		request.Protocol = strings.ToLower(request.Protocol)
	}

	requestURL := ""
	request.Domain = request.Headers["host"]
	requestURL = fmt.Sprintf("%s://%s%s", request.Protocol, request.Domain, request.Pathname)
	queryParams := request.Query
	// sort QueryParams by key
	q := url.Values{}
	for key, value := range queryParams {
		q.Add(key, value)
	}
	querystring := q.Encode()
	if len(querystring) > 0 {
		if strings.Contains(requestURL, "?") {
			requestURL = fmt.Sprintf("%s&%s", requestURL, querystring)
		} else {
			requestURL = fmt.Sprintf("%s?%s", requestURL, querystring)
		}
	}
	debugLog("> %s %s", request.Method, requestURL)

	httpRequest, err := http.NewRequest(request.Method, requestURL, request.Body)
	if err != nil {
		return
	}
	httpRequest.Host = request.Domain

	client := getToolClient(runtimeObject.GetClientTag(request.Domain))
	client.Lock()
	if !client.IfInit {
		trans, err := getHttpTransport(request, runtimeObject)
		if err != nil {
			return nil, err
		}
		client.HttpClient.Timeout = time.Duration(runtimeObject.ReadTimeout) * time.Millisecond
		client.HttpClient.Transport = trans
		client.IfInit = true
	}
	client.Unlock()
	for key, value := range request.Headers {
		if value == "" || key == "content-length" {
			continue
		} else if key == "host" {
			httpRequest.Header["Host"] = []string{value}
			delete(httpRequest.Header, "host")
		} else if key == "user-agent" {
			httpRequest.Header["User-Agent"] = []string{value}
			delete(httpRequest.Header, "user-agent")
		} else {
			httpRequest.Header[key] = []string{value}
		}
		debugLog("> %s: %s", key, value)
	}
	contentLength, _ := strconv.Atoi(request.Headers["content-length"])
	event := types.NewProgressEvent(TransferStartedEvent, 0, int64(contentLength), 0)
	types.PublishProgress(runtimeObject.Listener, event)

	putMsgToMap(fieldMap, httpRequest)
	startTime := time.Now()
	fieldMap["{start_time}"] = startTime.Format("2006-01-02 15:04:05")
	res, err := evanDo(client.HttpClient.Do)(httpRequest)
	fieldMap["{cost}"] = time.Since(startTime).String()
	completedBytes := int64(0)
	if runtimeObject.Tracker != nil {
		completedBytes = runtimeObject.Tracker.CompletedBytes
	}
	if err != nil {
		event = types.NewProgressEvent(TransferFailedEvent, completedBytes, int64(contentLength), 0)
		types.PublishProgress(runtimeObject.Listener, event)
		return
	}

	event = types.NewProgressEvent(TransferCompletedEvent, completedBytes, int64(contentLength), 0)
	types.PublishProgress(runtimeObject.Listener, event)

	response = NewResponse(res)
	fieldMap["{code}"] = strconv.Itoa(res.StatusCode)
	fieldMap["{res_headers}"] = transToString(res.Header)
	debugLog("< HTTP/1.1 %s", res.Status)
	for key, value := range res.Header {
		debugLog("< %s: %s", key, strings.Join(value, ""))
		if len(value) != 0 {
			response.Headers[strings.ToLower(key)] = value[0]
		}
	}
	return
}

// NewRuntimeObject is used for shortly create runtime object
func NewRuntimeObject(runtime map[string]interface{}) *types.RuntimeObject {
	if runtime == nil {
		return &types.RuntimeObject{}
	}

	runtimeObject := &types.RuntimeObject{
		IgnoreSSL:      TransInterfaceToBool(runtime["ignoreSSL"]),
		ReadTimeout:    TransInterfaceToInt(runtime["readTimeout"]),
		ConnectTimeout: TransInterfaceToInt(runtime["connectTimeout"]),
		LocalAddr:      TransInterfaceToString(runtime["localAddr"]),
		HttpProxy:      TransInterfaceToString(runtime["httpProxy"]),
		HttpsProxy:     TransInterfaceToString(runtime["httpsProxy"]),
		NoProxy:        TransInterfaceToString(runtime["noProxy"]),
		Socks5Proxy:    TransInterfaceToString(runtime["socks5Proxy"]),
		Socks5NetWork:  TransInterfaceToString(runtime["socks5NetWork"]),
		Key:            TransInterfaceToString(runtime["key"]),
		Cert:           TransInterfaceToString(runtime["cert"]),
		CA:             TransInterfaceToString(runtime["ca"]),
	}
	if runtime["listener"] != nil {
		runtimeObject.Listener = runtime["listener"].(types.ProgressListener)
	}
	if runtime["tracker"] != nil {
		runtimeObject.Tracker = runtime["tracker"].(*types.ReaderTracker)
	}
	if runtime["logger"] != nil {
		runtimeObject.Logger = runtime["logger"].(*types.Logger)
	}
	return runtimeObject
}

func TransInterfaceToBool(in interface{}) bool {
	if in != nil {
		return in.(bool)
	}
	return false
}
func TransInterfaceToInt(in interface{}) int {
	if in != nil {
		return in.(int)
	}
	return 0
}
func TransInterfaceToString(in interface{}) string {
	if in != nil {
		return in.(string)
	}
	return ""
}

func getToolClient(tag string) *types.ToolClient {
	client, ok := clientPool.Load(tag)
	if client == nil && !ok {
		client = &types.ToolClient{
			HttpClient: &http.Client{},
			IfInit:     false,
		}
		clientPool.Store(tag, client)
	}
	return client.(*types.ToolClient)
}

func getHttpTransport(req *types.Request, runtime *types.RuntimeObject) (*http.Transport, error) {
	trans := new(http.Transport)
	httpProxy, err := getHttpProxy(req.Protocol, req.Domain, runtime)
	if err != nil {
		return nil, err
	}
	if strings.ToLower(req.Protocol) == "https" &&
		runtime.Key != "" && runtime.Cert != "" {
		cert, err := tls.X509KeyPair([]byte(runtime.Cert), []byte(runtime.Key))
		if err != nil {
			return nil, err
		}

		trans.TLSClientConfig = &tls.Config{
			Certificates:       []tls.Certificate{cert},
			InsecureSkipVerify: runtime.IgnoreSSL,
		}
		if runtime.CA != "" {
			clientCertPool := x509.NewCertPool()
			ok := clientCertPool.AppendCertsFromPEM([]byte(runtime.CA))
			if !ok {
				return nil, errors.New("Failed to parse root certificate ")
			}
			trans.TLSClientConfig.RootCAs = clientCertPool
		}
	} else {
		trans.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: runtime.IgnoreSSL,
		}
	}
	if httpProxy != nil {
		trans.Proxy = http.ProxyURL(httpProxy)
		if httpProxy.User != nil {
			password, _ := httpProxy.User.Password()
			auth := httpProxy.User.Username() + ":" + password
			basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
			req.Headers["Proxy-Authorization"] = basic
		}
	}
	if runtime.Socks5Proxy != "" {
		socks5Proxy, err := getSocks5Proxy(runtime)
		if err != nil {
			return nil, err
		}
		if socks5Proxy != nil {
			var auth *proxy.Auth
			if socks5Proxy.User != nil {
				password, _ := socks5Proxy.User.Password()
				auth = &proxy.Auth{
					User:     socks5Proxy.User.Username(),
					Password: password,
				}
			}
			dialer, err := proxy.SOCKS5(strings.ToLower(runtime.Socks5NetWork), socks5Proxy.String(), auth,
				&net.Dialer{
					Timeout:   time.Duration(runtime.ConnectTimeout) * time.Millisecond,
					LocalAddr: getLocalAddr(runtime.LocalAddr),
				})
			if err != nil {
				return nil, err
			}
			trans.Dial = dialer.Dial
		}
	} else {
		trans.DialContext = setDialContext(runtime)
	}
	return trans, nil
}
func getHttpProxy(protocol, host string, runtime *types.RuntimeObject) (proxy *url.URL, err error) {
	urls := getNoProxy(runtime)
	for _, addr := range urls {
		if addr == host {
			return nil, nil
		}
	}
	if protocol == "https" {
		if runtime.HttpsProxy != "" {
			proxy, err = url.Parse(runtime.HttpsProxy)
		} else if rawUrl := os.Getenv("HTTPS_PROXY"); rawUrl != "" {
			proxy, err = url.Parse(rawUrl)
		} else if rawUrl := os.Getenv("https_proxy"); rawUrl != "" {
			proxy, err = url.Parse(rawUrl)
		}
	} else {
		if runtime.HttpProxy != "" {
			proxy, err = url.Parse(runtime.HttpProxy)
		} else if rawUrl := os.Getenv("HTTP_PROXY"); rawUrl != "" {
			proxy, err = url.Parse(rawUrl)
		} else if rawUrl := os.Getenv("http_proxy"); rawUrl != "" {
			proxy, err = url.Parse(rawUrl)
		}
	}
	return proxy, err
}
func getNoProxy(runtime *types.RuntimeObject) []string {
	var urls []string
	if runtime.NoProxy != "" {
		urls = strings.Split(runtime.NoProxy, ",")
	} else if rawUrl := os.Getenv("NO_PROXY"); rawUrl != "" {
		urls = strings.Split(rawUrl, ",")
	} else if rawUrl := os.Getenv("no_proxy"); rawUrl != "" {
		urls = strings.Split(rawUrl, ",")
	}
	return urls
}

func getSocks5Proxy(runtime *types.RuntimeObject) (proxy *url.URL, err error) {
	if runtime.Socks5Proxy != "" {
		proxy, err = url.Parse(runtime.Socks5Proxy)
	}
	return proxy, err
}
func getLocalAddr(localAddr string) (addr *net.TCPAddr) {
	if localAddr != "" {
		addr = &net.TCPAddr{
			IP: []byte(localAddr),
		}
	}
	return addr
}
func setDialContext(runtime *types.RuntimeObject) func(cxt context.Context, net, addr string) (c net.Conn, err error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if runtime.LocalAddr != "" {
			netAddr := &net.TCPAddr{
				IP: []byte(runtime.LocalAddr),
			}
			return (&net.Dialer{
				Timeout:   time.Duration(runtime.ConnectTimeout) * time.Second,
				LocalAddr: netAddr,
			}).DialContext(ctx, network, address)
		}
		return (&net.Dialer{
			Timeout: time.Duration(runtime.ConnectTimeout) * time.Second,
		}).DialContext(ctx, network, address)
	}
}

func putMsgToMap(fieldMap map[string]string, request *http.Request) {
	fieldMap["{host}"] = request.Host
	fieldMap["{method}"] = request.Method
	fieldMap["{uri}"] = request.URL.RequestURI()
	fieldMap["{pid}"] = strconv.Itoa(os.Getpid())
	fieldMap["{version}"] = strings.Split(request.Proto, "/")[1]
	hostname, _ := os.Hostname()
	fieldMap["{hostname}"] = hostname
	fieldMap["{req_headers}"] = transToString(request.Header)
	fieldMap["{target}"] = request.URL.Path + request.URL.RawQuery
}
func transToString(object interface{}) string {
	byt, _ := json.Marshal(object)
	return string(byt)
}
