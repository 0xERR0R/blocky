package helpertest

import (
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
)

// creates temp file with passed data
func TempFile(data string) *os.File {
	f, err := ioutil.TempFile("", "prefix")
	if err != nil {
		log.Fatal(err)
	}

	_, err = f.WriteString(data)
	if err != nil {
		log.Fatal(err)
	}

	return f
}

// creates temp http server with passed data
func TestServer(data string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		_, err := rw.Write([]byte(data))
		if err != nil {
			log.Fatal("can't write to buffer:", err)
		}
	}))
}
