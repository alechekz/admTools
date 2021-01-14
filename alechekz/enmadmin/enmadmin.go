package enmadm

import (
	"fmt"
	"log"
	"os"

	"alechekz/network"
	"golang.org/x/crypto/ssh"
)

//define struct of ENM parameter
type Param struct {
	Name    string //parameter name
	Default string //parameter default value
	Value   string //parameter value
	Range   string //parameter values range
	Desc    string //parameter description

}

func Read(params []*Param, host string) {

	// get ssh client configuration using function PrepSshClientConfig
	// that reads private keys and known hosts
	// and prepare configuration for certain user
	var config *ssh.ClientConfig = netHelper.PrepSshClientConfig("root")

	//dual client
	var mainhost string = "almaty-enm-master"
	client, err := ssh.Dial("tcp", mainhost+":22", config)
	if err != nil {
		log.Fatalln(err)
	}

	//print message of successful connection
	fmt.Printf("\n-> %s\n", mainhost)

	//read all required parameters
	for _, p := range params {

		//run cmd
		printout, err := netHelper.ExecCmd(
			client,
			os.Stdout,
			fmt.Sprintf("python /ericsson/pib-scripts/etc/config.py read --app_server_address=%s:8080 --name=%s", host, p.Name),
		)

		//error case
		if err != nil {
			log.Println(err)
			continue
		}

		//save value
		p.Value = printout[0]

	}

	//diconnect
	fmt.Printf("\n<- %s\n", mainhost)

}
