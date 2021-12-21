package main

import (
	error2 "acrossCloud/error"
	"acrossCloud/util"
	"fmt"
)

func main() {
	//use DoHttpToApiGateway 来发送http请求
	//appKey 阿里云网关AppKey
	//appSecret 阿里云网关AppSecret
	//domain 阿里云网关Domain
	//path  阿里云网关转发后path
	//method GET or POST
	//body 请求体
	//headers  请求头额外参数
	//use DoHttpsToApiGateway 来发送https请求
	headers := make(map[string]string)
	headers["Authorization"] = "111"
	resp, err := util.DoHttpsToApiGateway("",
		"",
		"",
		"/",
		"POST",
		``, nil)
	error2.PanicError(err)
	fmt.Println(resp)
}
