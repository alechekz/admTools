package fs

import (
	"math"
	"os"
	"path/filepath"
)

// DirSizeIn calculates summary of directory size and return it in Mb or Kb
func DirSizeIn(path, units string) float64 {

	//define a channel
	sizes := make(chan int64)

	//define function that returns a size of a file
	readSize := func(path string, file os.FileInfo, err error) error {

		//ignore errors
		if err != nil || file == nil {
			return nil
		}

		//send file size to channel
		if !file.IsDir() {
			sizes <- file.Size()
		}
		return nil
	}

	//run function to get all sizes
	go func() {
		filepath.Walk(path, readSize)
		close(sizes)
	}()

	//summary
	var size int64
	for s := range sizes {
		size += s
	}

	//return
	if units == "Kb" {
		return math.Round(float64(size) / 1024.0)
	}
	return math.Round(float64(size) / 1024.0 / 1024.0)

}
