package utils

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func TestEncryptAES256(t *testing.T) {
	got := make([]byte, 32)
	_, err := rand.Read(got)
	if err != nil {
		t.Error(err.Error())
	}
	fmt.Println(got, string(got))
	pText := []byte("123456789")
	res, err := EncryptAES256(pText, got)
	if err != nil {
		t.Error("This is test error" + err.Error())
	}
	fmt.Println("result is ", res)
}

func TestDecryptAES256(t *testing.T) {
	// got := make([]byte, 32)
	gotKey := []byte{174, 18, 6, 171, 200, 164, 200, 185, 153, 255, 134, 168, 75, 200, 111, 192, 128, 60, 221, 171, 241, 111, 113, 215, 143, 141, 247, 171, 83, 204, 127, 191}
	want := []byte("123456789")
	gotPwd := "NnADspy5aaksvL6+wXy9Ep8xSpypQosX6QC96a/6yxQ="
	res, err := DecryptAES256([]byte(gotPwd), gotKey)
	if err != nil {
		t.Error("This is test error" + err.Error())
	}
	if res != string(want) {
		t.Error("not match!!!")
	}
	fmt.Println("result is ", res, string(want))
}

func TestStudyFn(t *testing.T) {
	// StudyFn()
}
