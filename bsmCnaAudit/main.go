package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"

	"alechekz/common"
	"alechekz/healthcheck"
	"alechekz/network"
	"golang.org/x/crypto/ssh"
)

//before audit is executed lets say that it would passed successfully
var isPassed bool = true

// ExecAudit is the scenario of OSS Audit
func ExecAudit(config *ssh.ClientConfig, host string, detailed, summary *bytes.Buffer) {

	//dual client
	client, err := ssh.Dial("tcp", host+":22", config)
	if err != nil {
		log.Fatalln(err)
	}

	//print message of successful connection
	fmt.Fprintf(detailed, "\n-> %s\n", host)

	// #1: check BSM adjust-jobs execution result on OSS-RC
	hc.CheckBsmAdjusts(client, detailed)

	// #2: check CNA adjust-jobs execution result on OSS-RC
	hc.CheckCnaAdjusts(client, detailed)

	//diconnect
	fmt.Fprintf(detailed, "\n<- %s\n", host)

	//summary report
	if isPassed {
		isPassed = hc.AuditSummary(host, summary)
	} else {
		hc.AuditSummary(host, summary)
	}

}

func main() {

	// Define flag "-f".
	// If the flag is set when the program was run,
	// that means we want save program ouput to file instead of standard stdout.
	// Variable "filename" is contain the name of file
	// where the porgram's ouput shoud be saved.
	var filename string
	flag.StringVar(&filename, "f", "", "name of file where BSM/CNA Audit should be logged")
	fmt.Println(filename)

	// Define flag "-mail".
	// If the flag is set the program will send audit report by mail
	var toMail bool
	flag.BoolVar(&toMail, "mail", false, "true, if audit report should be send by mail")

	//parse flags
	flag.Parse()

	//define writer for detailed audit information
	var detailed *bytes.Buffer = common.NewBytesBuffer()

	//define writer for summary audit information
	var summary *bytes.Buffer = common.NewBytesBuffer()

	// get ssh client configuration using function PrepSshClientConfig
	// that reads private keys and known hosts
	// and prepare configuration for certain user
	var config *ssh.ClientConfig = netHelper.PrepSshClientConfig("root")

	//define an array of hosts where audit would be executed
	var hosts []string = []string{
		"astana-oss-master",
	}

	//print welcome message
	fmt.Fprintln(detailed, "BSM/CNA Audit Started:")

	//execute oss audit for each host in hosts
	for _, host := range hosts {

		//run the scenario of oss Audit on certain host
		ExecAudit(config, host, detailed, summary)

	}

	//print goodbye message
	fmt.Fprintln(detailed, "\nBSM/CNA Audit Finished")

	//print short result message
	var subject string
	if isPassed {
		subject = "Daily BSM/CNA Audit [PASSED]"
		fmt.Fprintln(detailed, "\n\n\t/// AUDIT IS PASSED ///\n\n")
	} else {
		subject = "Daily BSM/CNA Audit [FAILED]"
		fmt.Fprintln(detailed, "\n\n\t/// AUDIT IS FAILED ///\n\n")
	}

	// determine if the "filename" was given and the program output
	// should be written to the file or to stdout
	w, err := common.GetWriter(filename)

	//unable to mail if writer is incorrect
	if err != nil {
		toMail = false
	}

	//print summary and detailed information to common writer
	fmt.Fprintln(w, "\t/// BSM/CNA AUDIT SUMMARY INFORMATION ///")
	fmt.Fprintln(w, summary)
	fmt.Fprintln(w, "\n\t/// BSM/CNA AUDIT DETAILED INFORMATION ///\n")
	fmt.Fprintln(w, detailed)

	//right writer closing
	common.CloseWriter(w)

	//send audit report by mail
	if toMail {
		netHelper.EmailIt(filename, "OSS-Audit", subject, "aleche")
	}

}
