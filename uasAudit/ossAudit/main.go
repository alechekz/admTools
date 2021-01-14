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

	// #1: check states of Managed Componetns of OSS-RC
	hc.CheckMCs(client, detailed)

	// #2: analises the output of command vxprint and shows disks failed states
	hc.CheckDisks(client, detailed)

	// #3: run OSS-RC's native database healthcheck
	hc.CheckDBA(client, detailed)

	// #4: check status of Veritas Cluster Servers
	hc.CheckVeritas(client, detailed)

	// #5: checks the status of Versant database monitor
	hc.CheckVrstDataMon(client, detailed)

	// #6: check mode and status of all versant databases
	hc.CheckVrstDb(client, detailed)

	// #7: check space usage of all versant databases
	hc.CheckVrstDbSU(client, detailed)

	// #8: check, if the new critical alarms of versant databases appeared
	hc.MonVrstDb(client, detailed)

	// #9: checks existence of failed processes
	hc.CheckFailProc(client, detailed)

	// #10: check a log size of all connections to the server.
	// The log should not above 1GB, another way warn to backup
	// and delete the contents of the file
	hc.CheckWtmpx(client, detailed)

	// #11: checks SMF logs size for Sybase, files have to be less than 1MB
	hc.CheckSyLogSize(client, detailed)

	// #12: check sybase backup log, the backup of Sybase database
	// has to be executed every Sunday
	hc.CheckSyBackLog(client, detailed)

	// #13: monitor critical events from CIF "ERROR LOG" at today
	hc.MonErrLog(client, detailed)

	// #14: monitor critical events from "NETWORK_STATUS LOG"
	hc.MonNetLog(client, detailed)

	// #15: check all core files. Files should not exists
	hc.CheckCoreFiles(client, detailed)

	// #16: check all out of memory dump files. Files should not exists
	hc.CheckOutOfMem(client, detailed)

	// #17: check security status of COBRA and RMI/JMS
	hc.CheckSecurity(client, detailed)

	// #18: check sybase error log, severity level up to 16 are caused
	// by user mistakes
	hc.CheckSyErrLog(client, detailed)

	// #19: check for the occurrence of a Sybase Configurable Shared Memory Dump
	hc.CheckSyDump(client, detailed)

	// #20: validate daily output of crontab job for its successful completion
	// for job containing - /ericsson/syb/conf/diag_proc_cache_test.ks
	hc.ValDiagProcCache(client, detailed)

	// #21: check the remaining space for the OSS-RC Sybase databases
	// and their transaction log
	hc.CheckSyDb(client, detailed)

	// #22: monitor exports of configurations files in "SYSTEM EVENT LOG"
	hc.MonConfigExports(client, detailed)

	// #23: check general disks space usage
	hc.CheckOssDisksSU(client, detailed)

	// #24: check home directory space usage
	hc.CheckHomeSU(client, detailed)

	// #25: check moshell log directory space usage
	hc.CheckMoshellLogSU(client, detailed)

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
	flag.StringVar(&filename, "f", "", "name of file where OSS Audit should be logged")
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
	fmt.Fprintln(detailed, "OSS Audit Started:")

	//execute oss audit for each host in hosts
	for _, host := range hosts {

		//run the scenario of oss Audit on certain host
		ExecAudit(config, host, detailed, summary)

	}

	//print goodbye message
	fmt.Fprintln(detailed, "\nOSS Audit Finished")

	//print short result message
	var subject string
	if isPassed {
		subject = "Daily OSS Audit [PASSED]"
		fmt.Fprintln(detailed, "\n\n\t/// AUDIT IS PASSED ///\n\n")
	} else {
		subject = "Daily OSS Audit [FAILED]"
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
	fmt.Fprintln(w, "\t/// OSS AUDIT SUMMARY INFORMATION ///")
	fmt.Fprintln(w, summary)
	fmt.Fprintln(w, "\n\t/// OSS AUDIT DETAILED INFORMATION ///\n")
	fmt.Fprintln(w, detailed)

	//right writer closing
	common.CloseWriter(w)

	//send audit report by mail
	if toMail {
		netHelper.EmailIt(filename, "OSS-Audit", subject, "aleche")
	}

}
