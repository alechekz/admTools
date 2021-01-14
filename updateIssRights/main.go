package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"alechekz/common"
	"alechekz/network"
	"golang.org/x/crypto/ssh"
)

type Host struct {
	Name       string
	Port       string
	Delim      string
	Os         string
	Cmd, Users []string
}

// GetUsers open required database file, parse it and returns an array of ISS users
func GetUsers() []string {

	//define an empty array for users
	var users []string

	//define DB name
	var db string = filepath.Join("data", "issUsers")

	//parse users data
	for _, s := range common.GetFileStrings(db) {

		//skip empty strings
		if len(s) == 0 {
			continue
		}

		//skip comments
		if s[0] == '#' {
			continue
		}

		//get user and append it to array
		users = append(users, strings.Fields(s)[2])

	}

	//return users
	return users

}

// GetRights open required database file, parse it and returns an array of ISS users rights
func GetRights(datatype string) map[string]string {

	//define DB name of ISS Users Rigths
	var db string = filepath.Join("data", "issRights")

	//define a map for rights
	var rights map[string]string = make(map[string]string)

	//parse rights and prepare cmd
	for _, s := range common.GetFileStrings(db) {

		//skip string if there is no required datatype
		if !strings.Contains(s, datatype) {
			continue
		}

		//split string for fields of rights and destinations
		var l []string = strings.Fields(s)
		var right, dest string = l[0], l[2]

		//add to map
		rights[dest] = right

	}

	//return map
	return rights

}

// Prepare prepares commands for rights updating
func Prepare(host *Host, users []string, rights map[string]string) {

	//prepare users for certain host syntax
	for _, user := range users {
		host.Users = append(host.Users, host.Delim+":"+user)
	}

	//prepare cmd
	for dest, right := range rights {

		//define additional rights
		var myRight, mask string

		//define variable for cmd
		var cmd string

		//switch
		switch right {
		case "--x":
			myRight, mask = "rwx", "--x"
		case "-wx":
			myRight, mask = "rwx", "-wx"
		case "rwx":
			myRight, mask = "rwx", "rwx"
		case "r-x":
			myRight, mask = "rwx", "r-x"
		default:
			myRight, mask = "rw-", "r--"
		}

		//convert users array to string
		var usersStr string = strings.Join(host.Users, ":"+right+",")

		//cmd for ENM(RedHat)
		if host.Os == "linux" {
			cmd = fmt.Sprintf("setfacl -m %s:%s %s", usersStr, right, dest)

			//cmd for OSS(Solaris)
		} else {
			cmd = fmt.Sprintf("chmod A=user::%s,mask:%s,group::---,other::---,%s:%s %s", myRight, mask, usersStr, right, dest)
		}

		//add cmd to list
		host.Cmd = append(host.Cmd, cmd)

	}

}

// Update executes ISS files rights update for centain type of files
func Update(config *ssh.ClientConfig, host *Host, buff *bytes.Buffer) {

	//dual client
	client, err := ssh.Dial("tcp", host.Name+":"+host.Port, config)
	if err != nil {
		log.Fatalln(err)
	}

	//print message of successful connection
	fmt.Fprintf(buff, "\n-> %s\n", host.Name)

	//run prepared cmds
	for _, cmd := range host.Cmd {
		netHelper.ExecCmd(client, buff, cmd)
	}

	//diconnect
	fmt.Fprintf(buff, "\n<- %s\n", host.Name)

}

func main() {

	// Define flag "-t".
	// flag "-t" determines type of data which rights should be updated
	var datatype string
	flag.StringVar(&datatype, "t", "", "type of data which should be updated:\n\t- funcAndData\n\t- scenarios")

	//parse flags
	flag.Parse()

	//exit, if the datatype is not given
	if datatype == "" {
		fmt.Println("Syntax error: no datatype given")
		return
	}

	//define writer for execution report
	var buff *bytes.Buffer = common.NewBytesBuffer()

	//get an array of ISS users
	var users []string = GetUsers()

	//get an array of ISS users rights
	var rights map[string]string = GetRights(datatype)

	// get ssh client configuration using function PrepSshClientConfig
	// that reads private keys and known hosts
	// and prepare configuration for certain user
	var config *ssh.ClientConfig = netHelper.PrepSshClientConfig("aleche")

	//define an array of hosts to update
	var hosts []*Host = []*Host{
		&Host{
			Name:  "almaty-enm-amos",
			Port:  "5022",
			Delim: "u",
			Os:    "linux",
		},

		&Host{
			Name:  "astana-oss-uas1",
			Port:  "22",
			Delim: "user",
			Os:    "solaris",
		},
	}

	//print welcome message
	fmt.Fprintf(buff, "Start Rights Update for \"%s\" data type\n", datatype)

	//execute oss audit for each host in hosts
	for _, host := range hosts {

		//prepare cmds
		Prepare(host, users, rights)

		//update rigths
		Update(config, host, buff)

	}

	//print goodbye message
	fmt.Fprintln(buff, "\nRights Update Finished")

	// determine if the "filename" was given and the program output
	// should be written to the file or to stdout
	w, _ := common.GetWriter("")

	fmt.Fprintln(w, buff)

	//right writer closing
	common.CloseWriter(w)

}
