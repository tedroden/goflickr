
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
	"strings"
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
	AuthToken string	
	Method string
	Signature string
	args   map[string]string
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

type Photoset struct {
	Id string `xml:"id,attr"`
}

type UploadPhoto struct {
	Id string `xml:"photoid"`
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


type nopCloser struct {
	io.Reader
}

func (nopCloser) Close() error { return nil }

type Error string

func (e Error) Error() string {
	return string(e)
}


func (request *Request) PhotosetCreate(title string, photo_id string) Photoset {
	request.Method = "flickr.photosets.create"
	request.args = map[string]string{
		"title": title,
		"primary_photo_id": photo_id,
	}
	s, _ := request.doPost(endpoint)
	var upload Photoset
	err := xml.Unmarshal(*s, &upload)
	if err != nil {
		fmt.Printf("ERROR! %s\n", err)
	}
	return upload	
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
	request.args = map[string]string{
		"frob": frob.Payload,
	}
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


func (request *Request) doPost(url_ string) (response *[]byte, err error) {

	
	request.args["api_key"] = request.ApiKey
	request.args["method"] = request.Method
	request.args["auth_token"] = request.AuthToken
	request.args["api_sig"] = request.GetSig()
	fmt.Println(request.args)
	body := encodeQuery(request.args)
	
	req, err := http.NewRequest("POST", url_, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	
	response_body, err := ioutil.ReadAll(resp.Body)
	fmt.Println(string(response_body))
	return &response_body, err

}


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

	request.args["api_key"] = request.ApiKey

	boundary, end := "----###---###--flickr-go-rules", "\r\n"

	// Build out all of POST body sans file
	header := bytes.NewBuffer(nil)
	for k, v := range request.args {
		header.WriteString("--" + boundary + end)
		header.WriteString("Content-Disposition: form-data; name=\"" + k + "\"" + end + end)
		header.WriteString(v + end)
	}
	header.WriteString("--" + boundary + end)
	header.WriteString("Content-Disposition: form-data; name=\"photo\"; filename=\"" + filename + "\"" + end)
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
func (request *Request) Upload(filename string, filetype string) (*UploadPhoto, error) {
	request.args = make(map[string]string, 5)
	
	request.args["is_public"] = "0"
	request.args["is_family"] = "0"
	request.args["is_friend"] = "0"
	request.args["auth_token"] = request.AuthToken
	request.args["api_sig"] = request.GetSig()
	

	postRequest, err := request.buildPost(uploadEndpoint, filename, filetype)
	if err != nil {
		fmt.Printf("oops!: %s\n", err)
		return nil, err
	}

	bytes, err := sendPost(postRequest)

	var upload UploadPhoto
	err = xml.Unmarshal(*bytes, &upload)
	return &upload, err
	
}

func (request *Request) getArgsPlusN(n int) map[string]string {
	args := make(map[string]string, len(request.args) + n)
	for k, v := range request.args {
		args[k] = v
	}	
	return args
}

func (request *Request) AuthUrl(frob string, perms string) (url string) {
	request.args = map[string]string {
		"frob": frob,
		"perms": perms,
	}
	return request.getURL(authEndpoint)  + "&api_sig=" + request.GetSig()
}


func sendPost(postRequest *http.Request) (response *[]byte, err error) {
	// Create and use TCP connection (lifted mostly wholesale from http.send)
	client := &http.DefaultClient
	resp, err := client.Do(postRequest)

	if err != nil {
		return nil, err
	}
	rawBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	return &rawBody, err
}


