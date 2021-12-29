package util

import (
	"errors"
	types "github.com/iEvan-lhr/acrossCloud/type"
	"io/ioutil"
	"strings"
)

type AcrossCloud struct {
	AppKey    string
	AppSecret string
	Domain    string
	Path      string
	Method    string
	Body      string
	header    map[string]string
}

func (ac *AcrossCloud) SetHeader(key, value string) {
	if ac.header == nil {
		ac.header = map[string]string{key: value}
	} else {
		ac.header[key] = value
	}
}

func (ac AcrossCloud) DoApiGetWayResp(protocol string) (resp string, err error) {
	if protocol == "http" {
		return doHttpToApiGateway(ac.AppKey, ac.AppSecret, ac.Domain, ac.Path, ac.Method, ac.Body, ac.header)
	} else if protocol == "https" {
		return doHttpsToApiGateway(ac.AppKey, ac.AppSecret, ac.Domain, ac.Path, ac.Method, ac.Body, ac.header)
	} else {
		return "", errors.New("protocol Only in(http,https)")
	}
}
func doHttpToApiGateway(appKey, appSecret, domain, path, method, body string, headers map[string]string) (resp string, err error) {
	client := &types.Client{
		Domain:    domain,
		AppKey:    appKey,
		AppSecret: appSecret,
	}
	var runtimeObject = types.RuntimeOptions{}
	var request = types.VpcManagement{
		Body: body,
	}
	result, err := doRequest(&request, &runtimeObject, client, path, method, "http", headers)
	if result.Body == nil {
		return err.Error(), nil
	}
	all, err := ioutil.ReadAll(result.Body)
	return string(all), err
}
func doHttpsToApiGateway(appKey, appSecret, domain, path, method, body string, headers map[string]string) (resp string, err error) {
	client := &types.Client{
		Domain:    domain,
		AppKey:    appKey,
		AppSecret: appSecret,
	}
	var runtimeObject = types.RuntimeOptions{}
	var request = types.VpcManagement{
		Body: body,
	}
	result, err := doRequest(&request, &runtimeObject, client, path, method, "https", headers)
	if result.Body == nil {
		return err.Error(), nil
	}
	all, err := ioutil.ReadAll(result.Body)
	return string(all), err
}
func doRequest(request *types.VpcManagement, runtime *types.RuntimeOptions, client *types.Client, path, method, protocol string, execHeaders map[string]string) (result types.Response, err error) {
	resp, err := requestDo(path, protocol, method, "String", request.Body, execHeaders, *runtime, client)
	if err != nil {
		return result, err
	}
	if IsFail(resp.StatusCode) {
		err = types.NewSDKError(map[string]interface{}{
			"code":    resp.StatusCode,
			"message": resp.StatusMessage,
			"data": map[string]string{
				"requestId": resp.Headers["x-ca-request-id"],
				"message":   resp.Headers["x-ca-error-message"],
			},
		})
		return result, err
	}
	return resp, err
}

func requestDo(pathname string, protocol string, method string, bodyType string, body interface{}, header map[string]string, runtime types.RuntimeOptions, client *types.Client) (result types.Response, err error) {
	if err != nil {
		return result, err
	}
	runtimes := map[string]interface{}{
		"timeouted":      "retry",
		"readTimeout":    DefaultNumber(runtime.ReadTimeout, client.ReadTimeout),
		"connectTimeout": DefaultNumber(runtime.ConnectTimeout, client.ConnectTimeout),
		"httpProxy":      DefaultString(runtime.HttpProxy, client.HttpProxy),
		"httpsProxy":     DefaultString(runtime.HttpsProxy, client.HttpsProxy),
		"noProxy":        DefaultString(runtime.NoProxy, client.NoProxy),
		"retry": map[string]interface{}{
			"maxAttempts": DefaultNumber(runtime.MaxAttempts, 3),
		},
		"backoff": map[string]interface{}{
			"policy": DefaultString(runtime.BackoffPolicy, "no"),
			"period": DefaultNumber(runtime.BackoffPeriod, 1),
		},
		"ignoreSSL": runtime.IgnoreSSL,
	}

	resp := types.Response{}
	for retryTimes := 0; AllowRetry(runtimes["retry"], retryTimes); retryTimes++ {
		if retryTimes > 0 {
			backoffTime := GetBackoffTime(runtimes["backoff"], retryTimes)
			if backoffTime > 0 {
				Sleep(backoffTime)
			}
		}

		resp, err = func() (types.Response, error) {
			requests := NewRequest()
			requests.Protocol = DefaultString(client.Protocol, protocol)
			requests.Method = method
			requests.Pathname = pathname
			requests.Headers = Merge(map[string]string{
				"host":           client.Domain,
				"date":           GetDateUTCString(),
				"x-ca-timestamp": GetTimestamp(),
				"x-ca-nonce":     GetNonce(),
				"x-ca-key":       client.AppKey,
				"accept":         "application/json",
				"content-type":   "application/json",
				"x-ca-stage":     DefaultString(client.Stage, "RELEASE"),
			}, header)
			signedParams := make(map[string]string)
			if bodyType == "String" {
				requests.Headers["content-md5"] = GetContentMD5(body.(string))
				requests.Body = strings.NewReader(body.(string))
			}
			signedParams = Merge(signedParams,
				requests.Query)
			requests.Headers["x-ca-signature"] = GetSignatureV1(requests, signedParams, client.AppSecret)
			response, err := DoRequest(requests, runtimes)
			if err != nil {
				return result, err
			}
			result = *response
			return result, err
		}()
		if !Retryable(err) {
			break
		}
	}

	return resp, err
}
