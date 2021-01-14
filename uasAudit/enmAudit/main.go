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

// ExecAudit is the scenario of ENM Audit
func ExecAudit(config *ssh.ClientConfig, host string, detailed, summary *bytes.Buffer) {

	//dual client
	client, err := ssh.Dial("tcp", host+":22", config)
	if err != nil {
		log.Fatalln(err)
	}

	//print message of successful connection
	fmt.Fprintf(detailed, "\n-> %s\n", host)

	// #1. check /etc/bashrc file for custom settings
	hc.CheckBashrc(client, detailed)

	// #2. check that ipdatabase and nodesAliases files are up to date
	hc.CheckNodesFilesUpdate(client, detailed)

	// #3. check status of ENM RAM/CPU required to run all assigned VM's on a Blade
	hc.CheckHwResources(client, detailed)

	// #4. check state of VA NAS in ENM
	hc.CheckNas(client, detailed)

	// #5. check the SAN StoragePool usage
	hc.CheckStoragePool(client, detailed)

	// #6. check for stale mounts on MS and Peer Nodes
	hc.CheckStaleMount(client, detailed)

	// #7. check Filesystem Usage on MS, NAS and Peer Nodes
	hc.CheckNodeFs(client, detailed)

	// #8. check status of key lsb services on each Blade
	hc.CheckSystemService(client, detailed)

	// #9. check the state of the VCS clusters on the deployment
	hc.CheckVcsCluster(client, detailed)

	// #10. check state of VCS llt heartbeat network interfaces on the deployment
	hc.CheckVcsLltHeartbeat(client, detailed)

	// #11. check state of VCS service groups on the deployment
	hc.CheckVcsServiceGroup(client, detailed)

	// #12. checks status of consul cluster
	hc.CheckConsul(client, detailed)

	// #13. check paths to disks on DB nodes are all accessible
	hc.CheckMultipathActive(client, detailed)

	// #14. checks Puppet is enabled on all nodes
	hc.CheckPuppetEnabled(client, detailed)

	// #15. check if there are critical alerts on the SAN
	hc.CheckSanAlert(client, detailed)

	// #16. check MDT status
	hc.CheckMdt(client, detailed)

	// #17: run native full healthcheck recommended by Ericsson
	hc.EnmNativeHC(client, detailed)

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
	flag.StringVar(&filename, "f", "", "name of file where ENM Audit should be logged")

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
	var hosts []string = []string{"almaty-enm-master"}

	//print welcome message
	fmt.Fprintln(detailed, "ENM Audit Started:")

	//execute ENIQ audit for each host in hosts
	for _, host := range hosts {

		//run the scenario of ENIQ Audit on certain host
		ExecAudit(config, host, detailed, summary)

	}

	//print goodbye message
	fmt.Fprintln(detailed, "\nENM Audit Finished")

	//print short result message
	var subject string
	if isPassed {
		subject = "Daily ENM Audit [PASSED]"
		fmt.Fprintln(detailed, "\n\n\t/// AUDIT IS PASSED ///\n\n")
	} else {
		subject = "Daily ENM Audit [FAILED]"
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
	fmt.Fprintln(w, "\t/// ENM AUDIT SUMMARY INFORMATION ///")
	fmt.Fprintln(w, summary)
	fmt.Fprintln(w, "\n\t/// ENM AUDIT DETAILED INFORMATION ///\n")
	fmt.Fprintln(w, detailed)

	//right writer closing
	common.CloseWriter(w)

	//send audit report by mail
	if toMail {
		netHelper.EmailIt(filename, "ENM-Audit", subject, "aleche")
	}

}
