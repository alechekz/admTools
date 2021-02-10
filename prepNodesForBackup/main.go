// prepNodesForBackup
//
// The script opens ipdatabase parse it to get nodes names and
// distribute all node to different files.
// The number of files is the number of days in month

package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

//global vars
var (
	script     = filepath.Base(os.Args[0])                                                  //the name of script
	home       = filepath.Dir(os.Args[0])                                                   //directory where the script was run
	ipdatabase = home + "/ipdatabase"                                                       //full name of ipdatabase
	nrOfFiles  = 30                                                                         //number of files with the nodes, 30 is 1-30 days of month
	nodesFile  = func(n int) string { return fmt.Sprintf("%s/nodes/list_%v.txt", home, n) } //return the name of file with nodes
)

//init type for map of nodes
type nodesMap map[int][]string

// devideNodesToMap - devides all nodes in file into map with required number of nodes sets
func devideNodesToMap(file *os.File) (nodesMap, error) {

	//get new reader
	r := bufio.NewReader(file)

	//define files counter
	var counter int = 1

	//define an empty map
	var m = make(nodesMap, nrOfFiles)

	//read file
	for {

		//read string
		s, err := r.ReadString('\n')

		//end of file
		if err == io.EOF {
			break
		}

		//error case
		if err != nil {
			return m, err
		}

		//split string and get nodename
		var node string = strings.Fields(s)[0]

		//skip test nodes, RNCs, MGWs
		if strings.Contains(node, "RNC") ||
			strings.Contains(node, "test") ||
			strings.Contains(node, "TEST") ||
			(len(node) <= 7 && strings.Contains(node, "_")) {
			continue
		}

		//add to map
		m[counter] = append(m[counter], node)
		counter++

		//reset counter
		if counter > nrOfFiles {
			counter = 1
		}

	}

	//return
	return m, nil

}

// writeFromMapToFile - writes each element of map to separate file
func writeFromMapToFiles(m nodesMap) error {

	//write each element of map to separate file
	for k, nodes := range m {

		//create writer
		w, err := os.Create(nodesFile(k))
		if err != nil {
			return err
		}
		defer w.Close()

		//write nodes to file
		for _, node := range nodes {
			if _, err := w.WriteString(node + "\n"); err != nil {
				return err
			}
		}

		//report info
		fmt.Printf("%v nodes in %s\n", len(nodes), nodesFile(k))
	}

	//successfully executed
	return nil

}

func main() {

	//start
	log.Printf("%s start execution\n", script)

	//open ipdatabase
	file, err := os.Open(ipdatabase)
	if err != nil {
		log.Fatalln(err)
	}
	defer file.Close()

	//devide nodes to map
	m, err := devideNodesToMap(file)
	if err != nil {
		log.Fatalln(err)
	}

	//write each element of map to separate file
	if err = writeFromMapToFiles(m); err != nil {
		log.Fatalln(err)
	}

	//successfully executed
	log.Printf("%s successfully executes", script)

}
