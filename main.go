package main

import (
	"fmt"
	error2 "github.com/iEvan-lhr/acrossCloud/error"
	"github.com/iEvan-lhr/acrossCloud/util"
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
	ac := util.AcrossCloud{
		AppKey:    "",
		AppSecret: "",
		Domain:    "-cn-beijing.alicloudapi.com",
		Path:      "/",
		Method:    "POST",
		Body:      `{}`,
	}
	ac.SetHeader("Authorization", "SyJi4rCJWT9TcDEjKDTYN2S7DzmXI1Et8_bvX0xIsMw")
	//resp, err := ac.DoApiGetWayResp("http")
	resp, err := ac.DoApiGetWayResp("https")
	error2.PanicError(err)
	fmt.Println(resp)

}
