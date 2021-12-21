package error

import "log"

func PanicError(err error) {
	if err != nil {
		panic(err)
	}
}

func LogError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
