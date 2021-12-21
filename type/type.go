package types

import (
	error2 "acrossCloud/error"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Client struct {
	AppKey         string
	AppSecret      string
	Protocol       string
	Stage          string
	ReadTimeout    int
	ConnectTimeout int
	Body           string
	HttpProxy      string
	HttpsProxy     string
	NoProxy        string
	Domain         string
}

type Config struct {
	Domain         string `json:"domain" xml:"domain" require:"true"`
	Protocol       string `json:"protocol" xml:"protocol"`
	AppKey         string `json:"appKey" xml:"appKey" require:"true"`
	AppSecret      string `json:"appSecret" xml:"appSecret" require:"true"`
	Token          string `json:"token" xml:"token"`
	Stage          string `json:"stage" xml:"stage"`
	RegionId       string `json:"regionId" xml:"regionId"`
	ReadTimeout    int    `json:"readTimeout" xml:"readTimeout"`
	ConnectTimeout int    `json:"connectTimeout" xml:"connectTimeout"`
	LocalAddr      string `json:"localAddr" xml:"localAddr"`
	HttpProxy      string `json:"httpProxy" xml:"httpProxy"`
	HttpsProxy     string `json:"httpsProxy" xml:"httpsProxy"`
	NoProxy        string `json:"noProxy" xml:"noProxy"`
}

type VpcManagement struct {
	Body   string
	Header map[string]string `json:"header" xml:"header"`
}

func (v VpcManagement) SetBody(s string) {
	v.Body = s
}

type RuntimeOptions struct {
	IgnoreSSL      bool   `json:"ignoreSSL" xml:"ignoreSSL"`
	MaxAttempts    int    `json:"maxAttempts" xml:"maxAttempts"`
	BackoffPolicy  string `json:"backoffPolicy" xml:"backoffPolicy"`
	BackoffPeriod  int    `json:"backoffPeriod" xml:"backoffPeriod"`
	ReadTimeout    int    `json:"readTimeout" xml:"readTimeout"`
	ConnectTimeout int    `json:"connectTimeout" xml:"connectTimeout"`
	LocalAddr      string `json:"localAddr" xml:"localAddr"`
	HttpProxy      string `json:"httpProxy" xml:"httpProxy"`
	HttpsProxy     string `json:"httpsProxy" xml:"httpsProxy"`
	NoProxy        string `json:"noProxy" xml:"noProxy"`
	Socks5Proxy    string `json:"socks5Proxy" xml:"socks5Proxy"`
	Socks5NetWork  string `json:"socks5NetWork" xml:"socks5NetWork"`
}

// Request is used wrap http request
type Request struct {
	Protocol string
	Port     int
	Method   string
	Pathname string
	Domain   string
	Headers  map[string]string
	Query    map[string]string
	Body     io.Reader
}

type Response struct {
	Body          io.ReadCloser
	StatusCode    int
	StatusMessage string
	Headers       map[string]string
}

// RuntimeObject is used for converting http configuration
type RuntimeObject struct {
	IgnoreSSL      bool             `json:"ignoreSSL" xml:"ignoreSSL"`
	ReadTimeout    int              `json:"readTimeout" xml:"readTimeout"`
	ConnectTimeout int              `json:"connectTimeout" xml:"connectTimeout"`
	LocalAddr      string           `json:"localAddr" xml:"localAddr"`
	HttpProxy      string           `json:"httpProxy" xml:"httpProxy"`
	HttpsProxy     string           `json:"httpsProxy" xml:"httpsProxy"`
	NoProxy        string           `json:"noProxy" xml:"noProxy"`
	Key            string           `json:"key" xml:"key"`
	Cert           string           `json:"cert" xml:"cert"`
	CA             string           `json:"ca" xml:"ca"`
	Socks5Proxy    string           `json:"socks5Proxy" xml:"socks5Proxy"`
	Socks5NetWork  string           `json:"socks5NetWork" xml:"socks5NetWork"`
	Listener       ProgressListener `json:"listener" xml:"listener"`
	Tracker        *ReaderTracker   `json:"tracker" xml:"tracker"`
	Logger         *Logger          `json:"logger" xml:"logger"`
}

// ProgressListener listens progress change
type ProgressListener interface {
	ProgressChanged(event *ProgressEvent)
}

// ProgressEventType defines transfer progress event type
type ProgressEventType int

// ProgressEvent defines progress event
type ProgressEvent struct {
	ConsumedBytes int64
	TotalBytes    int64
	RwBytes       int64
	EventType     ProgressEventType
}

type ReaderTracker struct {
	CompletedBytes int64
}

type Logger struct {
	*log.Logger
	formatTemplate string
	isOpen         bool
	lastLogMsg     string
}

func (logger *Logger) PrintLog(fieldMap map[string]string, err error) {
	if err != nil {
		fieldMap["{error}"] = err.Error()
	}
	fieldMap["{time}"] = time.Now().Format("2006-01-02 15:04:05")
	fieldMap["{ts}"] = getTimeInFormatISO8601()
	fieldMap["{channel}"] = logChannel
	if logger != nil {
		logMsg := logger.formatTemplate
		for key, value := range fieldMap {
			logMsg = strings.Replace(logMsg, key, value, -1)
		}
		logger.lastLogMsg = logMsg
		if logger.isOpen == true {
			err = logger.Output(2, logMsg)
			error2.PanicError(err)
		}
	}
}
func getTimeInFormatISO8601() (timeStr string) {
	gmt := time.FixedZone("GMT", 0)

	return time.Now().In(gmt).Format("2006-01-02T15:04:05Z")
}

var logChannel string

func (r *RuntimeObject) GetClientTag(domain string) string {
	return strconv.FormatBool(r.IgnoreSSL) + strconv.Itoa(r.ReadTimeout) +
		strconv.Itoa(r.ConnectTimeout) + r.LocalAddr + r.HttpProxy +
		r.HttpsProxy + r.NoProxy + r.Socks5Proxy + r.Socks5NetWork + domain
}

type ToolClient struct {
	sync.Mutex
	HttpClient *http.Client
	IfInit     bool
}

// Auth contains authentication parameters that specific Dialer may require.
type Auth struct {
	User, Password string
}

func NewProgressEvent(eventType ProgressEventType, consumed, total int64, rwBytes int64) *ProgressEvent {
	return &ProgressEvent{
		ConsumedBytes: consumed,
		TotalBytes:    total,
		RwBytes:       rwBytes,
		EventType:     eventType}
}

func PublishProgress(listener ProgressListener, event *ProgressEvent) {
	if listener != nil && event != nil {
		listener.ProgressChanged(event)
	}
}

// SDKError struct is used save error code and message
type SDKError struct {
	Code       string
	StatusCode int
	Message    string
	Data       string
	Stack      string
	errMsg     string
}

func (err *SDKError) Error() string {
	if err.errMsg == "" {
		str := fmt.Sprintf("SDKError:\n   StatusCode: %d\n   Code: %s\n   Message: %s\n   Data: %s\n",
			err.StatusCode, err.Code, err.Message, err.Data)
		err.SetErrMsg(str)
	}
	return err.errMsg
}
func (err *SDKError) SetErrMsg(msg string) {
	err.errMsg = msg
}

// NewSDKError is used for shortly create SDKError object
func NewSDKError(obj map[string]interface{}) *SDKError {
	err := &SDKError{}
	if val, ok := obj["code"].(int); ok {
		err.Code = strconv.Itoa(val)
	} else if val, ok := obj["code"].(string); ok {
		err.Code = val
	}

	if statusCode, ok := obj["statusCode"].(int); ok {
		err.StatusCode = statusCode
	} else if status, ok := obj["statusCode"].(string); ok {
		statusCode, err2 := strconv.Atoi(status)
		if err2 == nil {
			err.StatusCode = statusCode
		}
	}

	if obj["message"] != nil {
		err.Message = obj["message"].(string)
	}
	if data := obj["data"]; data != nil {
		byt, _ := json.Marshal(data)
		err.Data = string(byt)
	}
	return err
}

type Data struct {
	Code  int    `json:"code"`
	Token Token  `json:"data"`
	Error string `json:"error"`
}

type Token struct {
	Val string `json:"token"`
}
