
package goflickr

import (
	"bytes"
	"crypto/md5"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sort"
)

const (
	endpoint        = "https://api.flickr.com/services/rest/?"
	uploadEndpoint  = "https://api.flickr.com/services/upload/"
	replaceEndpoint = "https://api.flickr.com/services/replace/"
	authEndpoint    = "https://www.flickr.com/services/auth/?"
	apiHost         = "api.flickr.com"
)

type Request struct {
	ApiKey string
	ApiSecret string
	Method string
	Signature string
	Args   map[string]string
}

type Response struct {
	Status  string         `xml:"stat,attr"`
	Error   *ResponseError `xml:"err"`
	Payload string         `xml:",innerxml"`
}

type ResponseError struct {
	Code    string `xml:"code,attr"`
	Message string `xml:"msg,attr"`
}

type Frob struct {
	Payload string `xml:"frob"`
}

type AuthUser struct {
	Fullname string `xml:"fullname,attr"`
	Nsid string `xml:"nsid,attr"`
	Username string `xml:"username,attr"`
}
type Auth struct {
	Token string `xml:"auth>token"`
	User AuthUser `xml:"auth>user"`
}


type nopCloser struct {
	io.Reader
}

func (nopCloser) Close() error { return nil }

type Error string

func (e Error) Error() string {
	return string(e)
}

func (request *Request) GetFrob() Frob {
	request.Method = "flickr.auth.getFrob"
	s, _ := request.doGet(endpoint)
	var f Frob
	xml.Unmarshal(s, &f)
	return f
}

func (request *Request) GetToken(frob Frob) Auth {
	request.Method = "flickr.auth.getToken"
	request.Args = request.getArgsPlusN(1)
	request.Args["frob"] = frob.Payload
	s, _ := request.doGet(endpoint)
	var a Auth
	xml.Unmarshal(s, &a)
	return a
}

func (request *Request) GetSig() string {
	args := request.getArgsPlusN(2)
	args["api_key"] = request.ApiKey
	if request.Method != "" {
		args["method"] = request.Method
	}

	// Sort array keys
	// fixme: got to bet a better way to sort these.
	sorted_keys := make([]string, len(args))
	i := 0
	for k := range args {
		sorted_keys[i] = k
		i++
	}
	sort.Strings(sorted_keys)
	// Build out ordered key-value string prefixed by secret
	s := request.ApiSecret
	for _, key := range sorted_keys {
		if args[key] != "" {
			s += fmt.Sprintf("%s%s", key, args[key])
		}
	}
	fmt.Println(s)
	// Have the full string, now hash
	hash := md5.New()
	hash.Write([]byte(s))	
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func (request *Request) Sign(secret string) {
	args := request.Args

	// Remove api_sig
	delete(args, "api_sig")

	sorted_keys := make([]string, len(args)+2)

	args["api_key"] = request.ApiKey
	args["method"] = request.Method

	// Sort array keys
	i := 0
	for k := range args {
		sorted_keys[i] = k
		i++
	}
	sort.Strings(sorted_keys)

	
	// Build out ordered key-value string prefixed by secret
	s := secret
	for _, key := range sorted_keys {
		if args[key] != "" {
			s += fmt.Sprintf("%s%s", key, args[key])
		}
	}

	// Since we're only adding two keys, it's easier
	// and more space-efficient to just delete them
	// them copy the whole map
	delete(args, "api_key")
	delete(args, "method")

	// Have the full string, now hash
	hash := md5.New()
	hash.Write([]byte(s))

	// Add api_sig as one of the args
	args["api_sig"] = fmt.Sprintf("%x", hash.Sum(nil))
}



// func (request *Request) URL() string {
// 	args := request.Args
// 	args["api_key"] = request.ApiKey
// 	if request.Method != "" {
// 		args["method"] = request.Method
// 	}
// 	if request.Signature != "" {
// 		args["api_sig"] = request.Signature
// 	}
// 	return endpoint + encodeQuery(args)
// }

func (request *Request) getURL(url_base string) string {
	args := request.getArgsPlusN(3)

	args["api_key"] = request.ApiKey
	if request.Method != "" {
		args["method"] = request.Method
	}
	if request.Signature != "" {
		args["api_sig"] = request.Signature
	}
	return url_base + encodeQuery(args)
}



func (request *Request) doGet(earl string) (response []byte, ret error) {
	if request.ApiKey == "" || request.Method == "" {
		return []byte(nil), Error("Need both API key and method")
	}

	request.Signature = request.GetSig()
	
	s := request.getURL(earl)

	res, err := http.Get(s)
	defer res.Body.Close()
	if err != nil {
		return []byte(nil), err
	}
	request.Signature = ""
	request.Method = ""	
	body, _ := ioutil.ReadAll(res.Body)
	return body, nil
}



// func (request *Request) Execute() (response []byte, ret error) {
// 	if request.ApiKey == "" || request.Method == "" {
// 		return []byte(nil), Error("Need both API key and method")
// 	}

// 	request.Signature = request.GetSig()
	
// 	s := request.URL()

// 	res, err := http.Get(s)
// 	defer res.Body.Close()
// 	if err != nil {
// 		return []byte(nil), err
// 	}

// 	body, _ := ioutil.ReadAll(res.Body)
// 	return body, nil
// }

func encodeQuery(args map[string]string) string {
	i := 0
	s := bytes.NewBuffer(nil)
	for k, v := range args {
		if i != 0 {
			s.WriteString("&")
		}
		i++
		s.WriteString(k + "=" + url.QueryEscape(v))
	}
	return s.String()
}

func (request *Request) buildPost(url_ string, filename string, filetype string) (*http.Request, error) {
	real_url, _ := url.Parse(url_)

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	f_size := stat.Size()

	request.Args["api_key"] = request.ApiKey

	boundary, end := "----###---###--flickr-go-rules", "\r\n"

	// Build out all of POST body sans file
	header := bytes.NewBuffer(nil)
	for k, v := range request.Args {
		header.WriteString("--" + boundary + end)
		header.WriteString("Content-Disposition: form-data; name=\"" + k + "\"" + end + end)
		header.WriteString(v + end)
	}
	header.WriteString("--" + boundary + end)
	header.WriteString("Content-Disposition: form-data; name=\"photo\"; filename=\"photo.jpg\"" + end)
	header.WriteString("Content-Type: " + filetype + end + end)

	footer := bytes.NewBufferString(end + "--" + boundary + "--" + end)

	body_len := int64(header.Len()) + int64(footer.Len()) + f_size

	r, w := io.Pipe()
	go func() {
		pieces := []io.Reader{header, f, footer}

		for _, k := range pieces {
			_, err = io.Copy(w, k)
			if err != nil {
				w.CloseWithError(nil)
				return
			}
		}
		f.Close()
		w.Close()
	}()

	http_header := make(http.Header)
	http_header.Add("Content-Type", "multipart/form-data; boundary="+boundary)

	postRequest := &http.Request{
		Method:        "POST",
		URL:           real_url,
		Host:          apiHost,
		Header:        http_header,
		Body:          r,
		ContentLength: body_len,
	}
	return postRequest, nil
}

// Example:
// r.Upload("thumb.jpg", "image/jpeg")
func (request *Request) Upload(filename string, filetype string, token string) (response *Response, err error) {
	request.Args = request.getArgsPlusN(5)
	
	request.Args["is_public"] = "0"
	request.Args["is_family"] = "0"
	request.Args["is_friend"] = "0"
	request.Args["auth_token"] = token
	request.Args["api_sig"] = request.GetSig()
	postRequest, err := request.buildPost(uploadEndpoint, filename, filetype)
	if err != nil {
		return nil, err
	}
	return sendPost(postRequest)
}

func (request *Request) getArgsPlusN(n int) map[string]string {
	args := make(map[string]string, len(request.Args) + n)
	for k, v := range request.Args {
		args[k] = v
	}	
	return args
}

func (request *Request) AuthUrl(frob string, perms string) (url string) {
	request.Args = request.getArgsPlusN(2)
	request.Args["frob"] = frob
	request.Args["perms"] = perms
	return request.getURL(authEndpoint)  + "&api_sig=" + request.GetSig()
}


func (request *Request) Replace(filename string, filetype string) (response *Response, err error) {
	postRequest, err := request.buildPost(replaceEndpoint, filename, filetype)
	if err != nil {
		return nil, err
	}
	return sendPost(postRequest)
}


func sendPost(postRequest *http.Request) (response *Response, err error) {
	// Create and use TCP connection (lifted mostly wholesale from http.send)
	client := &http.DefaultClient
	resp, err := client.Do(postRequest)

	if err != nil {
		return nil, err
	}
	rawBody, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	var r Response
	err = xml.Unmarshal(rawBody, &r)

	return &r, err
}


