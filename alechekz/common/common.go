package common

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// GetWriter determines if the "filename" was given.
// If it is and the file was sucessffully created
// the function return file as writer.
// If the "filename" is empty string or incorrect the function returns stdout as writer
func GetWriter(filename string) (io.Writer, error) {

	//empty string
	if filename == "" {
		return os.Stdout, errors.New("No file name")
	}

	//create new file
	file, err := os.Create(filename)

	//handle an error
	if err != nil {
		log.Println(err)
		log.Println("stdout was returned as writer\n")
		return os.Stdout, err
	}

	//return file writer
	return bufio.NewWriter(file), nil

}

// NewBytesBuffer return pointer of new buffer of bytes
func NewBytesBuffer() *bytes.Buffer {

	//init bytes buffer
	var buff bytes.Buffer

	//return
	return &buff

}

// CloseWriter check if the writer type is *bufio.Writer
// and close it correctly
func CloseWriter(w io.Writer) {

	//get type of writer
	switch w.(type) {

	//if *bufio.Writer found close it
	case *bufio.Writer:

		//close or report an error
		err := w.(*bufio.Writer).Flush()
		if err != nil {
			log.Fatalln(err)
		}

	}

}

// IsStrInArr returns true if an array contains the given string and false if not
func IsStrInArr(arr []string, elem string) bool {

	//check an array
	for _, s := range arr {

		//check element
		if s == elem {
			return true
		}

	}

	//not found
	return false

}

// GetFileStrings reads file content and returns it as slice of strings
func GetFileStrings(file string) []string {

	//open file
	content, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatalln(err)
	}

	//split content to the slice of strings and return
	return strings.Split(string(content), "\n")

}

// GetDirStrings reads directory content and returns it as slice of strings
func GetDirStrings(dir string) []string {

	//define an empty array of strings
	var files []string

	//get dir content
	content, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatalln(err)
	}

	//add dir content to files
	for _, f := range content {
		files = append(files, f.Name())
	}

	//return
	return files

}

// GetHome returns temporary, predefined home directoryif the program
// was run as 'go run' and the real one, if the program was compiled
func GetHome(temp string) string {

	//get absolut program name
	ex, err := os.Executable()
	if err != nil {
		log.Fatalln(err)
	}

	//return temp/predefined home, if the program was run as 'go run'
	if strings.Contains(ex, "tmp/") {
		return temp
	}

	//return real home
	return filepath.Dir(ex)

}
