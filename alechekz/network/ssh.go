package netHelper

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"alechekz/common"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

//package constants
const (

	// MailUser is the user of main server
	MailUser string = "aleche"

	// MailServer is the host where the mail server is up
	MailServer string = "astana-oss-uas2"
)

// PrepSshClientConfig reads private keys and known hosts
// and return ssh client configuration
func PrepSshClientConfig(user string) *ssh.ClientConfig {

	//read my private key file
	rsaId, _ := ioutil.ReadFile(filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa"))

	//get the signer for this private key
	signer, _ := ssh.ParsePrivateKey(rsaId)

	//parse known_hosts to get server keys
	hostKeyCallback, _ := knownhosts.New(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))

	//init ssh client configuration
	return &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{

			//use the PublicKeys method for remote authentication.
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}

}

// ExecCmd initiate new session on client, run the command on it
// and return the command respond as an array of strings
func ExecCmd(client *ssh.Client, w io.Writer, cmd string) ([]string, error) {

	//init new session to client
	session, _ := client.NewSession()
	defer session.Close()

	//run cmd
	fmt.Fprintf(w, "\n->> %s\n", cmd)
	printout, err := session.CombinedOutput(cmd)

	//return the cmd respond as an array of strings and error
	return strings.Split(string(printout), "\n"), err

}

// EmailIt copies file to remote mail server and
// sends mail by execution mailx on mail server by ssh
func EmailIt(filename, from, subject, mailgroup string) {

	//define map of mail lists
	var to map[string][]string = map[string][]string{
		"admins": []string{
			"alexey.cheremissov@kcell.kz",
			"galina.zhumayeva@kcell.kz",
			"askar.bekmurzayev@kcell.kz",
		},
		"aleche": []string{"alexey.cheremissov@kcell.kz"},
		"cc": []string{
			"ControlCenter@kcell.kz",
			"alexey.cheremissov@kcell.kz",
		},
	}

	//get required mail list
	var maillist string = strings.Join(to[mailgroup], ", ")

	//define cmd for copying file to remote server
	var cmd *exec.Cmd = exec.Command("scp", filename, MailUser+"@"+MailServer+":")

	//copy file to remote server
	_, err := cmd.Output()
	if err != nil {
		log.Fatalln(err)
	}

	// get ssh client configuration using function PrepSshClientConfig
	// that reads private keys and known hosts
	// and prepare configuration for certain user
	var config *ssh.ClientConfig = PrepSshClientConfig(MailUser)

	//dual client
	client, _ := ssh.Dial("tcp", MailServer+":22", config)

	//define cmd for sending mail from the mail server
	var file string = filepath.Base(filename)
	var mailx string = fmt.Sprintf(
		"cat %s | mailx -r \"%s\" -s \"%s\" \"%s\"",
		file,
		from,
		subject,
		maillist,
	)

	//send mail from the mail server
	ExecCmd(client, os.Stdout, mailx)

	//remove file from remote server
	ExecCmd(client, os.Stdout, "rm "+file)

}

// EmailErr closes writer and sends an error by mail
func EmailErr(filename, from, subject, mailgroup string, w io.Writer, err error) {

	//print error massage
	fmt.Fprintln(w, err)

	//right writer closing
	common.CloseWriter(w)

	//send error by mail
	EmailIt(filename, from, subject, mailgroup)

	//exit
	log.Fatalln(err)

}
