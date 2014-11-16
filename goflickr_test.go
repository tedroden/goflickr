package goflickr

import (
	"fmt"
	"os"
	"os/exec"
	"log"
	"time"
	"testing"
)

const (
	OPEN_COMMAND = "xdg-open"
)


var (
	API_KEY = os.Getenv("FLICKR_KEY")
	API_SECRET = os.Getenv("FLICKR_SECRET")
	TOKEN = os.Getenv("FLICKR_TOKEN")
	FROB Frob
	AUTH Auth
	UploadedPhotoId string
)



func sanity() {
	if API_KEY == "" || API_SECRET == ""  {
		log.Panic("Both FLICKER_KEY, FLICKR_SECRET environment variables need to be set")
	}
	if AUTH.Token == "" {
		log.Panic("No auth object! Try again.")
	}
}

func init() {
	fmt.Println("Testing 3 methods during init!")
	fmt.Println("(these need to go first)")
	testFrobGet()
	testAuthUrl()
	testGetToken()
	fmt.Println("Done, continuing with regular tests!")
}


func testFrobGet() {
	fmt.Println("Testing FrobGet")
	r := &Request{
		ApiKey: API_KEY,
		ApiSecret: API_SECRET,		
	}	
	FROB = r.FrobGet()
	fmt.Println("/testGetFrob")
}

func testAuthUrl() {
	fmt.Println("Testing AuthUrl()")
	r := &Request{
		ApiKey: API_KEY,
		ApiSecret: API_SECRET,		
	}		
	auth_url := r.AuthUrl(FROB.Payload, "write")
	fmt.Println(auth_url)
	cmd := exec.Command(OPEN_COMMAND, auth_url)
	err := cmd.Run()
	if err != nil {
		log.Panic(err)
	}	
	fmt.Println("Go to your browser and authenticate.")
	fmt.Println("Waiting 10 seconds...")
	time.Sleep(10 * time.Second)
	fmt.Println("Done.")
}

func testGetToken() {
	fmt.Println("Testing Get Token")
	r := &Request{
		ApiKey: API_KEY,
		ApiSecret: API_SECRET,		
	}	
	AUTH = r.GetToken(FROB)
	fmt.Println("Done.")
}

func TestUpload(t *testing.T) {
	sanity()
	r := &Request{
		ApiKey: API_KEY,
		ApiSecret: API_SECRET,
		AuthToken: AUTH.Token,
	}
	fmt.Println(AUTH)
	photo, err := r.Upload("test-image.png", "image/png")
	if err != nil {
		log.Println(err)
		t.Fail()
	}
	UploadedPhotoId = photo.Id
}

func TestPhotosetCreate(t *testing.T) {
	sanity()

	// can't do this until we have a photo id
	for UploadedPhotoId == "" {
		time.Sleep(1 * time.Second)
	}

	r := &Request{
		ApiKey: API_KEY,
		ApiSecret: API_SECRET,
		AuthToken: AUTH.Token,
	}
	set := r.PhotosetCreate("goflickr test set", UploadedPhotoId)
	fmt.Println("Created set!")
	fmt.Println(set)
}
