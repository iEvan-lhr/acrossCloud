package util

import (
	"fmt"
	"net/http"
	"time"
)

func GetDateUTCString() string {
	return time.Now().UTC().Format(http.TimeFormat)
}

func GetTimestamp() string {
	return fmt.Sprintf("%v", time.Now().UnixNano()/1000000)
}
