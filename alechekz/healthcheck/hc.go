package hc

import (
	"fmt"
	"io"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"alechekz/common"
	"alechekz/network"
	"golang.org/x/crypto/ssh"
)

const (

	// DfThreshold is the threshold of system disk space usage
	DfThreshold = 40

	// NumOfStrForSingleBE is the number of strings
	// for printout of single ZFS Boot Environment
	NumOfStrForSingleBE = 4

	// ParsedEntriesThreshold is the threshold of number of parsed entries from oss
	ParsedEntriesThreshold = 250

	// SyDbThreshold is the threshold of sybase databases allowed capacity
	SyDbThreshold = 80

	// VrstDbThreshold is the threshold of versant databases allowed capacity
	VrstDbThreshold = 30

	// JobsThreshold is the threshold of allowed number of exports jobs per user in OSS-RC
	JobsThreshold = 10

	// HomeSizeThreshold is the threshold of allowed size of users home directory
	HomeSizeThreshold = 10

	// MoshellLogSizeThreshold is the threshold of allowed size
	// of users  moshell log directory
	MoshellLogSizeThreshold = 5

	// TimestampOfLastVrstCriticalAlarm is the string timestamp of the last critical
	// alarm of versant databases
	TimestampOfLastVrstCriticalAlarm = "***** Mon Nov  9 19:33:14 QYZT 2020  *****"

	// UptimeThreshold is the number of day the system is up and running.
	// Only during these days the check will show an error of server up time
	UptimeThreshold = 14
)

//init a map of checks and it's results
var Checks map[string]bool = make(map[string]bool)

//init a map of functions description
var description map[string]string = map[string]string{
	"CheckDisksSU":                 "checks file system disk space usage",
	"CheckOssDisksSU":              "checks OSS-RC general disks space usage",
	"CheckBeadm":                   "checks the lists all existing ZFS Boot Environments(BEs), should be only one with if there is no preparation for system upgrade",
	"CheckSrvs":                    "checks services states, all required services should be online",
	"CheckSnapshots":               "checks all available snapshots, autocreated snapshots has \"snss\" in name",
	"CheckETLC":                    "check activities in ENIQ ETLC Monitoring",
	"EnmNativeHC":                  "runs native full healthcheck recommended by Ericsson and analyze the output",
	"CheckMCs":                     "checks states of Managed Componetns of OSS-RC",
	"CheckDisks":                   "analises the output of command vxprint and show disks failed states",
	"CheckSyDb":                    "checks the remaining space for the OSS-RC Sybase databases and their transaction log",
	"CheckVrstDataMon":             "checks the status of Versant database monitor",
	"CheckFailProc":                "checks existence of failed processes",
	"CheckWtmpx":                   "checks a log size of all connections to the server, the log should not above 1GB, another way warn to backup and delete the contents of the file",
	"CheckSyLogSize":               "checks SMF logs size for Sybase, files have to be less than 1MB",
	"CheckSyErrLog":                "checks sybase error log, severity level up to 16 are caused by user mistakes",
	"CheckSyBackLog":               "checks sybase backup log, The backup of Sybase database has to be executed every Sunday",
	"MonErrLog":                    "monitors critical events from CIF \"ERROR LOG\" at today",
	"MonConfigExports":             "monitors exports of configurations files in \"SYSTEM EVENT LOG\"",
	"MonNetLog":                    "monitors critical events from \"NETWORK_STATUS LOG\"",
	"MonRestarts":                  "monitors nodes manual restarts, by select entries which record contains 'restart' from \"COMMAND LOG\"",
	"ValDiagProcCache":             "validates daily output of crontab job for its successful completion for job containing - /ericsson/syb/conf/diag_proc_cache_test.ks",
	"CheckCoreFiles":               "checks all core files, files should not exists",
	"CheckOutOfMem":                "checks all out of memory dump files, files should not exists",
	"CheckSecurity":                "checks security status of COBRA and RMI/JMS",
	"CheckVeritas":                 "checks status of Veritas Cluster Servers",
	"CheckSyDump":                  "checks for the occurrence of a Sybase Configurable Shared Memory Dump",
	"CheckHomeSU":                  "checks home directory space usage",
	"CheckMoshellLogSU":            "checks moshell logs directory space usage",
	"CheckDBA":                     "runs OSS-RC's native database healthcheck",
	"CheckVrstDb":                  "checks mode and status of all versant databases",
	"CheckVrstDbSU":                "checks space usage of all versant databases",
	"MonVrstDb":                    "checks if the new critical alarms if versant databases appeared",
	"CheckBsmAdjusts":              "checks BSM adjust-jobs execution result on OSS-RC",
	"CheckCnaAdjusts":              "checks CNA adjust-jobs execution result on OSS-RC",
	"KillOldSessions":              "checks users session and kills the old one",
	"CheckNrOfBackupPolicies":      "checks if the number of backup policies on the OMBS is consistent with the required one",
	"CheckNetBackupClients":        "checks connection between OMBS and NetBackup's clients",
	"CheckBackupPoliciesSchedExec": "checks if the required backup policies in scheduler were executed",
	"CheckHwResources":             "checks status of ENM RAM/CPU required to run all assigned VM's on a Blade",
	"CheckNas":                     "checks state of VA NAS in ENM",
	"CheckStoragePool":             "checks the SAN StoragePool usage",
	"CheckStaleMount":              "checks for stale mounts on MS and Peer Nodes",
	"CheckNodeFs":                  "checks Filesystem Usage on MS, NAS and Peer Nodes",
	"CheckOmbsBackup":              "checks OMBS backups and displays a list of recent backups",
	"CheckSystemService":           "checks status of key lsb services on each Blade",
	"CheckVcsCluster":              "checks the state of the VCS clusters on the deployment",
	"CheckVcsLltHeartbeat":         "checks state of VCS llt heartbeat network interfaces on the deployment",
	"CheckVcsServiceGroup":         "checks state of VCS service groups on the deployment",
	"CheckFcaps":                   "runs FCAPS summary of the system",
	"CheckConsul":                  "checks status of consul cluster",
	"CheckMultipathActive":         "checks paths to disks on DB nodes are all accessible",
	"CheckPuppetEnabled":           "checks Puppet is enabled on all nodes",
	"CheckSanAlert":                "checks if there are critical alerts on the SAN",
	"CheckMdt":                     "checks MDT status",
	"CheckZfsPoolStatus":           "checks the status of ZFS pool file systems",
	"CheckZfsPoolSU":               "checks ZFS pool space usage",
	"CheckZfsPoolErrors":           "checks if there are any error in ZFS pool",
	"DeepCheckETLC":                "performs deep analise of activities in ENIQ ETLC Monitoring",
	"FindParsedInKnown":            "checks that all parsed entries of ETLC are known already",
	"FindKnownInParsed":            "checks that all known entries of ETLC are found in the today's log",
	"CompareNumParsed":             "compares the number of parsed entries of ETLC with required one",
	"CheckSrvsUptime":              "checks each service which must be available on certain host to ensure that the service start time was not updated",
	"CheckHostUptime":              "checks host uptime to ensure that it was not restarted",
	"CheckMountingOk":              "checks, if all required disk are mounted properly",
	"CheckBashrc":                  "checks /etc/bashrc file for custom settings",
	"CheckNodesFilesUpdate":        "checks that ipdatabase and nodesAliases files are up to date",
}

// CmdFailed prints an error message and
// set healthcheck execution flag to unsuccessful
func CmdFailed(check string, w io.Writer) {
	Checks[check] = false
	fmt.Fprintln(w, "\tnok\tcommand execution failed")
}

// CmdFailOk prints a message about successfully healthcheck execution
func CmdFailOk(message string, w io.Writer) {
	fmt.Fprintf(w, "\tok\t%s\n", message)
}

// AuditSummary prints summary audit information
// and returns true or false depends of all checks result
func AuditSummary(host string, w io.Writer) bool {

	//print summary information
	fmt.Fprintf(w, "\n%s:\n", host)
	for check, ok := range Checks {
		if ok {
			fmt.Fprintf(w, "ok\t%s - %s\n", check, description[check])
		} else {
			fmt.Fprintf(w, "nok\t%s - %s\n", check, description[check])
		}
	}

	//return summary result
	for _, ok := range Checks {
		if !ok {
			Checks = map[string]bool{}
			return false
		}
	}
	Checks = map[string]bool{}
	return true

}

// CheckDisksSU checks file system disk space usage
func CheckDisksSU(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckDisksSU"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run "df -h | awk '{print $5$1}'"
	printout, err := netHelper.ExecCmd(
		client,
		w,
		"df -h | awk '{print $5$1}'",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		return
	}

	//check printout
	for _, s := range printout {

		//split string to disk and space usage
		var l []string = strings.Split(s, "%")
		su, err := strconv.Atoi(l[0])
		if err != nil {
			continue
		}
		var disk = l[1]

		//print report info
		if su < DfThreshold {
			fmt.Fprintf(w, "\tok\t%v%s\t%s\n", su, "%", disk)
		} else {
			fmt.Fprintf(w, "\tnok\t%v%s\t%s\n", su, "%", disk)

			//test is failed
			Checks[name] = false

		}

	}
}

// CheckOssDisksSU checks OSS-RC general disks space usage
func CheckOssDisksSU(client *ssh.Client, w io.Writer) {

	//init map of disks thresholds
	var threshold map[string]int = map[string]int{
		"/ossrc/sybdev/oss/sybdata":  91,
		"/ossrc/sybdev/sybmaster":    63,
		"/ossrc/dbdumps":             20,
		"/ossrc/sybdev/fm/fmsyblog":  95,
		"/ossrc/sybdev/pm/pmsyblog":  70,
		"/ossrc/sybdev/pm/pmsybdata": 90,
		"/ossrc/sybdev/fm/fmsybdata": 95,
		"/ossrc/sybdev/oss/syblog":   91,
		"/export":                    27,
		"/ossrc/upgrade":             1,
		"/ossrc/versant":             11,
		"/ossrc/3pp":                 92,
		"/var/opt/ericsson":          70,
	}

	//init check name
	var name string = "CheckOssDisksSU"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run "df -lh | egrep '^/dev/vx/dsk' | awk '{print $5 "\t\t" $6}'"
	printout, err := netHelper.ExecCmd(
		client,
		w,
		"df -lh | egrep '^/dev/vx/dsk' | awk '{print $5$6}'",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//check for the mode and status of all databases
	for _, s := range printout {

		//skip empty strings
		if len(s) == 0 {
			continue
		}

		//split string to space usage and disk
		var l []string = strings.Split(s, "%")
		var disk string = l[1]
		su, err := strconv.Atoi(l[0])

		//handle an error case
		if err != nil {
			CmdFailed(name, w)
			fmt.Fprintln(w)
			return
		}

		//print report info
		if su <= threshold[disk] {
			fmt.Fprintf(w, "\tok\t%v%s\t%s\n", su, "%", disk)
		} else {
			fmt.Fprintf(w, "\tnok\t%v%s\t%s\n", su, "%", disk)

			//test is failed
			Checks[name] = false

		}

	}

}

// CheckBeadm checks the lists all existing ZFS Boot Environments(BEs)
// should be only one with if there is no preparation for system upgrade
func CheckBeadm(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckBeadm"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run "beadm list"
	printout, err := netHelper.ExecCmd(
		client, w,
		"beadm list",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		return
	}

	//print report info
	if len(printout) <= NumOfStrForSingleBE {
		fmt.Fprintln(w, "\tok\tonly one Boot Environment found")
	} else {
		fmt.Fprintln(w, "\tnok\tthe ZFS pool has more than one Boot Environment")

		//test is falied
		//Checks[name] = false

	}

}

// CheckSnapshots checks all available snapshots.
// Autocreated snapshots has "snss" in name.
// Applicable for eniq-coordinator only
func CheckSnapshots(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckSnapshots"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//before check is executed lets say that it would passed successfully
	Checks["CheckSnapshots"] = true

	//get current year
	var year string = strconv.Itoa(time.Now().Year())

	//run "bash /eniq/bkup_sw/bin/prep_eniq_snapshots.bsh -u -N"
	printout, err := netHelper.ExecCmd(
		client,
		w,
		"bash /eniq/bkup_sw/bin/prep_eniq_snapshots.bsh -u -N | grep "+year,
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		return
	}

	//check printout
	for _, str := range printout {

		//skip empty string
		if len(str) == 0 {
			continue
		}

		//print report info
		if str[:4] == "snss" {
			fmt.Fprintf(w, "\tok\t%s\n", str)
		} else {
			fmt.Fprintf(w, "\tnok\t%s\n", str)

			//test is failed
			Checks[name] = false

		}

	}

}

// CheckETL check activities in ENIQ ETLC Monitoring
// Applicable for eniq-engine only
func CheckETLC(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckETLC"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//get current date
	var now string = time.Now().Format(time.RFC3339)
	var d string = strings.ReplaceAll(strings.Split(now, "T")[0], "-", "_")

	//run "grep -i parsed /eniq/log/sw_log/engine/engine-2020_10_07.log"
	for _, oss := range []string{"oss_2", "oss_3"} {

		//run cmd for oss
		printout, err := netHelper.ExecCmd(
			client,
			w,
			"grep -i parsed /eniq/log/sw_log/engine/engine-"+d+".log | grep "+oss,
		)

		//handle an error case
		if err != nil {
			CmdFailed(name, w)
			continue
		}

		//print report info
		var entries = len(printout)
		if entries > ParsedEntriesThreshold {
			fmt.Fprintf(w, "\tok\tnumber of parsed entries(%v) for %s is more than %v\n", entries, oss, ParsedEntriesThreshold)
		} else {
			fmt.Fprintf(w, "\tnok\tnumber of parsed entries(%v) for %s is less than %v\n", entries, oss, ParsedEntriesThreshold)

			//test is failed
			Checks[name] = false

		}

	}

}

// EnmNativeHC runs native full healthcheck recommended by Ericsson and analyze the output
func EnmNativeHC(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "EnmNativeHC"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run "/opt/ericsson/enminst/bin/enm_healthcheck.sh --verbose"
	printout, err := netHelper.ExecCmd(
		client, w,
		"/opt/ericsson/enminst/bin/enm_healthcheck.sh --verbose",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
	}

	//print report infor
	for _, s := range printout {
		fmt.Fprintln(w, s)
	}

}

// CheckMCs checks states of Managed Componetns of OSS-RC
func CheckMCs(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckMCs"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run "/opt/ericsson/bin/smtool -l | egrep -v 'started|unlicensed'"
	printout, err := netHelper.ExecCmd(
		client,
		w,
		"/opt/ericsson/bin/smtool -l | egrep -v \"started|unlicensed\"",
	)

	//if the command returned an error this means that the check is passed successfully
	if err != nil {
		CmdFailOk("no any failed MCs", w)
		return
	}

	//show failed MCs
	for _, s := range printout {

		//skip an empty strings
		if len(s) == 0 {
			continue
		}

		//split capacity load and filesystem fields
		var mc []string = strings.Fields(s)

		//print report info
		fmt.Fprintf(w, "\tnok\t%s(%s)\n", mc[0], mc[1])

	}

	//test is failed
	Checks[name] = false

}

// CheckDisks analises the output of command vxprint and show disks failed states
func CheckDisks(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckDisks"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run "vxprint"
	printout, err := netHelper.ExecCmd(
		client,
		w,
		"vxprint | egrep -i \"iofail|recover\"",
	)

	//if the command returned an error this means that the check is passed successfully
	if err != nil {
		CmdFailOk("no any failed disks", w)
		return
	}

	//print report info
	for _, s := range printout {

		//split capacity load and filesystem fields
		var l []string = strings.Fields(s)

		//skip empty strings
		if len(s) == 0 {
			continue
		}

		//print report info
		fmt.Fprintf(w, "\tnok\t{%s}-{%s}-{%s} => {%s|%s}\n", l[0], l[1], l[2], l[3], l[6])

	}

	//test is failed
	Checks[name] = false

}

// CheckSyDb checks the remaining space for the OSS-RC Sybase databases
// and their transaction log
func CheckSyDb(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckSyDb"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run cmd
	printout, err := netHelper.ExecCmd(
		client,
		w,
		"su - sybase -c /ericsson/syb/util/db_check.sh | egrep ' system'")

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//check printout
	for _, s := range printout[1:] {

		//skip empty strings
		if len(s) == 0 {
			continue
		}

		//split on fields each string
		var l []string = strings.Fields(s)

		//get required params
		var db string = l[0]
		su, err := strconv.Atoi(strings.TrimRight(l[5], "%"))

		//handle an error case
		if err != nil {
			CmdFailed(name, w)
			fmt.Fprintln(w)
			return
		}

		//print report info
		if su < SyDbThreshold {
			fmt.Fprintf(w, "\tok\t%v%s\t%s\n", su, "%", db)
		} else {
			fmt.Fprintf(w, "\tnok\t%v%s\t%s\n", su, "%", db)

			//test is failed
			Checks[name] = false

		}

	}

}

// CheckVrstDataMon checks the status of Versant database monitor
func CheckVrstDataMon(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckVrstDataMon"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run "svcs versant_log_monitor"
	printout, err := netHelper.ExecCmd(
		client,
		w,
		"svcs versant_log_monitor")

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//split to state and name
	var l []string = strings.Fields(printout[1])

	//check printout
	if l[0] == "online" {
		fmt.Fprintf(w, "\tok\t%s\n", l[2])
	} else {
		fmt.Fprintf(w, "\tnok\t%s(%s)\n", l[2], l[0])

		//test is failed
		Checks[name] = false

	}

}

// CheckFailProc checks existence of failed processes
func CheckFailProc(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckFailProc"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run "ls -l /var/tmp/failed_process"
	printout, err := netHelper.ExecCmd(
		client,
		w,
		"ls -l /var/tmp/failed_process")

	//if the command returned an error this means that the check is passed successfully
	if err != nil {
		CmdFailOk("no any failed process temp files", w)
		return
	}

	//split file info string
	var l []string = strings.Fields(printout[0])

	//print report info
	fmt.Fprintf(w, "\tnok\t%s\n", l[len(l)-1])

	//test is failed
	Checks[name] = false

}

// CheckWtmpx checks a log size of all connections to the server.
// The log should not above 1GB, another way warn to backup
// and delete the contents of the file
func CheckWtmpx(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckWtmpx"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run "du -sh /var/adm/wtmpx"
	printout, err := netHelper.ExecCmd(
		client,
		w,
		"du -sh /var/adm/wtmpx")

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//print report info
	var size string = strings.Fields(printout[0])[0]
	if !strings.Contains(size, "G") {
		fmt.Fprintf(w, "\tok\tthe log size(%s) of all server connection is less than 1GB\n", size)
	} else {
		fmt.Fprintf(w, "\tnok\tthe log size(%s) of all server connection is more than 1GB\n", size)

		//test is failed
		Checks[name] = false

	}

}

// CheckSyLogSize checks SMF logs size for Sybase,
// files have to be less than 1MB
func CheckSyLogSize(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckSyLogSize"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run "du -sh /var/svc/log/ericsson-eric_3pp-sybase_[lp]*"
	printout, err := netHelper.ExecCmd(
		client,
		w,
		"du -sh /var/svc/log/ericsson-eric_3pp-sybase_[lp]*")

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//check printout
	for _, s := range printout {

		//skip empty strings
		if len(s) == 0 {
			continue
		}

		//print report info
		var size string = strings.Fields(s)[0]
		var file string = strings.Fields(s)[1]
		if !strings.Contains(size, "M") {
			fmt.Fprintf(w, "\tok\tthe size(%s) of %s is less than 1MB\n", size, file)
		} else {
			fmt.Fprintf(w, "\tnok\tthe size(%s) of %s is more than 1MB\n", size, file)

			//test is failed
			Checks[name] = false

		}

	}

}

// CheckNrOfBackupPolicies checks if the number of policies on the OMBS
// is consistent with the required one
func CheckNrOfBackupPolicies(client *ssh.Client, host string, w io.Writer) {

	//init check name
	var name string = "CheckNrOfBackupPolicies"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//init map of number of policies for each ombs
	var policies map[string]int = map[string]int{
		"almaty-oss-ombs": 15,
		"astana-oss-ombs": 13,
	}

	//run cmd
	printout, err := netHelper.ExecCmd(
		client,
		w,
		"/usr/openv/netbackup/bin/admincmd/bppllist -L")

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//print report info
	var n int = len(printout) - 1
	if n == policies[host] {
		fmt.Fprintln(w, "\tok\tthe number of policies is consistent with the required one")
	} else if n > policies[host] {
		fmt.Fprintf(
			w,
			"\tnok\tlooks like new policy was added, %v instead of %v\n",
			n,
			policies[host],
		)

		//test is failed
		Checks[name] = false

	} else {
		fmt.Fprintf(
			w,
			"\tnok\tlooks like policy was deleted, %v instead of %v\n",
			n,
			policies[host],
		)

		//test is failed
		Checks[name] = false

	}

}

// CheckSyErrLog checks sybase error log,
// severity level up to 16 are caused by user mistakes
func CheckSyErrLog(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckSyErrLog"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//get current date
	var now string = time.Now().Format(time.RFC3339)
	var d string = strings.ReplaceAll(strings.Split(now, "T")[0], "-", "/")

	//get cmd
	var cmd string = fmt.Sprintf(
		"grep error /var/opt/sybase/sybase/log/masterdataservice.ERRORLOG | grep %s",
		d,
	)

	//run "grep error masterdataservice.ERRORLOG | grep current_date"
	printout, err := netHelper.ExecCmd(
		client, w, cmd)

	//handle an error case
	if err != nil {
		CmdFailOk("no errors in sybase errorlog", w)
		return
	}

	//print errors
	fmt.Fprintln(w, "\tnoc\tthere are errors in masterdataservice.ERRORLOG\n")
	for _, s := range printout {
		fmt.Fprintf(w, "\t\t%s\n", s)
	}

	//test is failed
	Checks[name] = false

}

// CheckSyBackLog checks sybase backup log.
// The backup of Sybase database has to be executed every Sunday
func CheckSyBackLog(client *ssh.Client, w io.Writer) {

	//get current time
	var now time.Time = time.Now()

	//check if backup should been made today
	if now.Weekday().String() != "Sunday" {
		return
	}

	//init check name
	var name string = "CheckSyBackLog"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//form cmd
	var cmd string = fmt.Sprintf(
		"cat /var/opt/sybase/sybase/log/masterdataservice_BACKUP.ERRORLOG | perl -nE 'print $_, if /%s\\h+%v/'",
		now.Month().String()[:3],
		now.Day(),
	)

	//run cmd
	printout, err := netHelper.ExecCmd(client, w, cmd)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//print report info
	if len(printout) > 400 {
		fmt.Fprintf(w, "\tok\tsybase backup was successfully executed(%v)\n", len(printout))
	} else {
		fmt.Fprintln(w, "\tnok\tlooks like sybase backup was failed")

		//test is failed
		Checks[name] = false

	}

}

// MonErrLog monitors critical events from CIF "ERROR LOG" at today
func MonErrLog(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "MonErrLog"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//get current date
	var now string = time.Now().Format(time.RFC3339)
	var d string = strings.Split(now, "T")[0]

	//form cmd
	var cmd string = fmt.Sprintf(
		"/opt/ericsson/nms_cif_sm/bin/log -type %s -filter \"severity_level = 3 AND time_stamp >= '%s'\"",
		"error",
		d,
	)

	//run example opt/ericsson/nms_cif_sm/bin/log
	//	-type error
	//	-filter "severity_level = 3 AND time_stamp >= '2020-10-24'"
	printout, err := netHelper.ExecCmd(client, w, cmd)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//print report info
	if len(printout) <= 1 {
		CmdFailOk("there is no critical errors in CIF log at today", w)
		return
	}

	//print errors
	fmt.Fprintln(w, "\tnok\tcheck critical errors of CIF log\n")
	for _, s := range printout {

		//skip empty and short strings
		if len(s) < 3 {
			continue
		}

		//print short info
		var head string = s[:3]
		if (head == "FDN") || (head == "Sho") || (head == "***") || (head == "Add") {
			fmt.Fprintf(w, "\t\t%s\n", s)
		}

	}

	//test is failed
	Checks[name] = false

}

// MonConfigExports monitors exports of configurations files in "SYSTEM EVENT LOG"
func MonConfigExports(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "MonConfigExports"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//get current date
	var now string = time.Now().Format(time.RFC3339)
	var d string = strings.Split(now, "T")[0]

	//form cmd
	var cmd string = fmt.Sprintf(
		"/opt/ericsson/nms_cif_sm/bin/log -type %s -filter \"event_type LIKE 'COM.ERICSSON.NMS.CIF.AM.NEW_JOB' AND time_stamp >= '%s'\" | grep Owner",
		"system",
		d,
	)

	//run example /opt/ericsson/nms_cif_sm/bin/log
	// -type system
	// -filter "event_type LIKE 'COM.ERICSSON.NMS.CIF.AM.NEW_JOB'
	//		AND time_stamp >= '2020-10-26'" | grep "Owner"
	printout, err := netHelper.ExecCmd(client, w, cmd)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//create a map
	var jobsCounter map[string]int = make(map[string]int)

	//check printout
	for _, s := range printout {

		//skip empty strings
		if len(s) == 0 {
			continue
		}

		//get job owner
		var owner string = strings.Trim(strings.Split(s, ":")[1], " ")

		//count owners jobs
		_, ok := jobsCounter[owner]
		if ok {
			jobsCounter[owner]++
		} else {
			jobsCounter[owner] = 1
		}

	}

	//print report info
	for owner, jobs := range jobsCounter {
		if jobs <= JobsThreshold || owner == "daikud" {
			fmt.Fprintf(w, "\tok\t%v\tjobs run by %s\n", jobs, owner)
		} else {
			fmt.Fprintf(w, "\tnok\t%v\tjobs run by %s\n", jobs, owner)

			//test is failed
			Checks[name] = false

		}

	}

}

// MonNetLog monitors critical events from "NETWORK_STATUS LOG"
func MonNetLog(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "MonNetLog"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//get current date
	var now string = time.Now().Format(time.RFC3339)
	var d string = strings.Split(now, "T")[0]

	//form cmd
	var cmd string = fmt.Sprintf(
		"/opt/ericsson/nms_cif_sm/bin/log -type %s -filter \"severity_level = 3 AND time_stamp >= '%s'\"",
		"security",
		d,
	)

	//run example /opt/ericsson/nms_cif_sm/bin/log
	// -type security
	// -filter "severity_level = 1 AND time_stamp >= '2020-10-26'
	printout, err := netHelper.ExecCmd(client, w, cmd)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//print report info
	if len(printout) <= 1 {
		CmdFailOk("there is no critical security events in CIF log at today", w)
		return
	}

	//print errors
	fmt.Fprintln(w, "\tnok\tcheck critical security events of CIF log\n")
	for _, s := range printout {

		//skip empty strings
		if len(s) == 0 {
			continue
		}

		//print short info
		var head string = s[:3]
		if (head == "FDN") || (head == "Sho") || (head == "***") || (head == "Add") {
			fmt.Fprintf(w, "\t\t%s\n", s)
		}

	}

	//test is failed
	Checks[name] = false

}

// MonRestarts monitors nodes manual restarts
// by select entries which record contains 'restart' from "COMMAND LOG"
func MonRestarts(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "MonRestarts"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//define an array of user to whom allowed to execute restart
	var noc []string = []string{
		"tdsemen",
		"td_egosh",
		"artgal",
		"aidtul",
		"stakos",
		"alelis",
		"bekkal",
		"yerkal",
		"dmileo",
		"zhakosba",
		"magber",
		"yevbarn",
		"andnov",
		"olmesh",
		"aindui",
		"maruse",
		"alymus",
		"igonau",
		"ruszan",
		"nurzha",
		"gilyev",
		"marakm",
		"almism",
		"dmizak",
		"yersai",
		"zhazha",
		"aziabd",
		"manzho",
		"irilee",
		"aksnur",
		"tolsad",
		"osmmam",
		"td_bater",
		"aiybat",
	}

	//get current date
	var now string = time.Now().Format(time.RFC3339)
	var d string = strings.Split(now, "T")[0]

	//form cmd
	var cmd string = fmt.Sprintf(
		"/opt/ericsson/nms_cif_sm/bin/log -type %s -filter \"command_name LIKE '%s' AND time_stamp >= '%s'\" | grep User",
		"command",
		"acc%restart%",
		d,
	)

	//run example /opt/ericsson/nms_cif_sm/bin/log
	// -type command
	// -filter "command_name LIKE '%restart'
	// AND time_stamp >= '2020-10-26'" | grep User
	printout, err := netHelper.ExecCmd(client, w, cmd)

	//handle an error case
	if err != nil {
		CmdFailOk("no nodes restarts found", w)
		fmt.Fprintln(w)
		return
	}

	//get an array of users to whom restricted to execute restarts but they did
	var notNoc []string
	for _, s := range printout {

		//skip an empty strings
		if len(s) == 0 {
			continue
		}

		//split the string to get the user
		var user string = strings.Trim(strings.Split(s, ":")[1], " ")

		//skip users who are in the list of noc users
		if common.IsStrInArr(noc, user) {
			continue
		}

		//skip users who are in the list of not noc users already
		if common.IsStrInArr(notNoc, user) {
			continue
		}

		//add to notNoc group
		notNoc = append(notNoc, user)

	}

	//print report info
	if len(notNoc) == 0 {
		fmt.Fprintln(w, "\tok\tonly users from NOC group executed restarts during requested period")
		return
	} else {
		fmt.Fprintf(w,
			"\tnok\t%s not allowed to execute restarts\n",
			notNoc,
		)
	}

	//test is failed
	Checks[name] = false

	//get additional restart info
	for _, user := range notNoc {

		//form cmd
		var cmd string = fmt.Sprintf(
			"/opt/ericsson/nms_cif_sm/bin/log -type %s -filter \"command_name LIKE '%s' AND time_stamp >= '%s' AND user_id LIKE '%s'\"",
			"command",
			"acc%restart%",
			d,
			user,
		)

		//run example /opt/ericsson/nms_cif_sm/bin/log
		// -type command
		// -filter "command_name LIKE '%restart'
		// AND time_stamp >= '20201026'
		// AND user_id LIKE 'anashe'"
		printout, err := netHelper.ExecCmd(client, w, cmd)

		//handle an error case
		if err != nil {
			CmdFailed(name, w)
			fmt.Fprintln(w)
			return
		}

		//print additional audit report
		for _, s := range printout {

			//skip empty strings
			if len(s) == 0 {
				continue
			}

			//print short info
			var head string = s[:3]
			if head == "Add" {

				//the last word of the string is ipAddress or nodename, check it
				var l []string = strings.Fields(s)
				var node string = l[len(l)-1]
				if len(strings.Split(node, ".")) != 4 {

					//print report info
					fmt.Fprintf(w, "\tWarning : %s restarted %s\n", user, node)
					fmt.Fprintf(w, "\t%s\n", s)

					//find and add nodename
				} else {

					//run cmd to get nodename
					printout, err := netHelper.ExecCmd(
						client,
						w,
						fmt.Sprintf("grep \"%s\" /opt/ericsson/amos/moshell/sitefiles/ipdatabase", node),
					)

					//handle an error case
					if err != nil {
						CmdFailed(name, w)
						fmt.Fprintln(w)
						return
					}

					//get nodename
					var nodename string = strings.Fields(printout[0])[0]

					//add nodename and print report info
					fmt.Fprintf(w, "\tWarining : %s restarted %s\n", user, nodename)
					fmt.Fprintf(w, "\t%s\n", s)

				}

			}

		}

	}

}

// ValDiagProcCach validates daily output of crontab job for its successful completion
// for job containing - /ericsson/syb/conf/diag_proc_cache_test.ks
func ValDiagProcCache(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "ValDiagProcCache"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run "tail -4 /ericsson/syb/log/diag_proc_cache_test.txt"
	printout, err := netHelper.ExecCmd(
		client,
		w,
		"tail -4 /ericsson/syb/log/diag_proc_cache_test.txt")

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//print report info
	if (strings.Contains(printout[1], "JSAGENT running - OK")) &&
		(strings.Contains(printout[3], "no action necessary")) {
		fmt.Fprintln(w, "\tok\tvalidation of Diagnostics Total Procedure Cache")
		return
	} else {
		fmt.Fprintln(w, "\tnoc\tvalidation of Diagnostics Total Procedure Cache\n")
	}

	//test is failed
	Checks[name] = false

	//print additional report info
	for i, s := range printout {
		fmt.Fprintf(w, "\t\t%v, %s\n", i, s)
	}

}

// CheckCoreFiles checks all core files. Files should not exists
func CheckCoreFiles(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckCoreFiles"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run "ls -erth /var/share/cores"
	printout, err := netHelper.ExecCmd(
		client,
		w,
		"ls -erth /var/share/cores")

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//if the command returned an error this means that the check is passed successfully
	if len(printout) == 2 {
		CmdFailOk("no any core files", w)
		return
	}

	//print report info
	fmt.Fprintln(w, "\tnok\tcore files found\n")

	//print additional report info
	for _, s := range printout {

		//skip empty strings
		if len(s) == 0 {
			continue
		}

		//print report info
		fmt.Fprintf(w, "\t\t%s\n", s)

	}

	//test is failed
	Checks[name] = false

}

// CheckOutOfMem checks all out of memory dump files. Files should not exists
func CheckOutOfMem(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckOutOfMem"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run "ls -erth /ossrc/upgrade/*/"
	printout, err := netHelper.ExecCmd(
		client,
		w,
		"ls -erth /ossrc/upgrade/*/*")

	//if the command returned an error this means that the check is passed successfully
	if err != nil {
		CmdFailOk("no any out of memory dump files", w)
		return
	}

	//print report info
	fmt.Fprintln(w, "\tnok\tout of memory dump files found\n")

	//print additional report info
	for _, s := range printout {

		//split the ouput string
		var l []string = strings.Fields(s)

		//skip unusefull strings
		if len(l) <= 2 {
			continue
		}

		//print report info
		fmt.Fprintf(w, "\t\t%s\t%s %s,%s\t%s\n", l[2], l[8], l[5], l[6], l[9])

	}

	//test is failed
	Checks[name] = false

}

// CheckSecurity checks security status of COBRA and RMI/JMS
func CheckSecurity(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckSecurity"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run "/opt/ericsson/secpf/scripts/bin/security.ksh -status"
	printout, err := netHelper.ExecCmd(
		client,
		w,
		"/opt/ericsson/secpf/scripts/bin/security.ksh -status")

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//print report info
	var ok string = "Currently set to ON"
	if (printout[1] == ok) && (printout[4] == ok) {
		fmt.Fprintln(w, "\tok\tsecurity status")
		return
	}

	//print report fail info
	fmt.Fprintln(w, "\tnok\tsecurity status\n")
	for _, s := range printout {
		if len(s) > 0 {
			fmt.Fprintf(w, "\t\t%s\n", s)
		}
	}

	//test is failed
	Checks[name] = false

}

// CheckVeritas checks status of Veritas Cluster Servers
func CheckVeritas(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckVeritas"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run "/opt/VRTSvcs/bin/hagrp -state"
	printout, err := netHelper.ExecCmd(
		client,
		w,
		"/opt/VRTSvcs/bin/hagrp -state | grep State | grep -v ONLINE")
	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//check prinout
	for _, s := range printout {

		//skip empty strings
		if len(s) == 0 {
			continue
		}

		//split printout string
		var l []string = strings.Fields(s)
		var group, system, state string = l[0], l[2], l[3]

		//print report info
		if (group[:3] == "Oss" && strings.Contains(system, "1bl")) ||
			(group[:3] == "Syb" && strings.Contains(system, "2bl")) {
			fmt.Fprintf(w, "\tok\t%s\t%s %s\n", group, state, system)
		} else {
			fmt.Fprintf(w, "\tnok\t%s\t%s %s\n", group, state, system)

			//test is failed
			Checks[name] = false

		}

	}

}

// CheckSyDump checks for the occurrence of a Sybase Configurable Shared Memory Dump
func CheckSyDump(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckSyDump"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run "su - sybase -c /ericsson/syb/conf/csmd_check"
	printout, err := netHelper.ExecCmd(
		client,
		w,
		"su - sybase -c /ericsson/syb/conf/csmd_check")

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//check printout
	for _, s := range printout {

		if strings.Contains(s, "csmd") {
			fmt.Fprintln(w, "\tnoc\tSybase Configurable Shared Memory Dump found\n")
			fmt.Fprintf(w, "\t\t%s\n", s)

			//test is failed
			Checks[name] = false
			return

		}

	}

	//no dump found
	fmt.Fprintln(w, "\tok\tno any Sybase Configurable Shared Memory Dump")

}

// CheckHomeSU checks home directory space usage
func CheckHomeSU(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckHomeSU"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run "du -sh /home/*"
	printout, err := netHelper.ExecCmd(
		client,
		w,
		"du -sh /home/*")

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//check printout
	for _, s := range printout {

		//skip, if the size is less than 1Gb
		if !strings.Contains(s, "G") {
			continue
		}

		//get dir and dir size
		var l []string = strings.Split(s, "G")
		var dir string = l[1]
		var s float64

		//convert size
		if size, err := strconv.ParseFloat(strings.Trim(l[0], " "), 32); err == nil {
			s = math.Floor(size)
		}

		//print report info
		if s < HomeSizeThreshold {
			fmt.Fprintf(w, "\tok\t%vG\t%s\n", s, dir)
		} else {
			fmt.Fprintf(w, "\tnok\t%vG\t%s\n", s, dir)

			//test is failed
			Checks[name] = false

		}

	}

	//test passed
	if Checks[name] {
		fmt.Fprintln(w, "\tok\tthere is no big directories found")
	}

}

// CheckMoshellLogSU checks moshell logs directory space usage
func CheckMoshellLogSU(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckMoshellLogSU"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run "du -sh /var/opt/ericsson/amos/moshell_logfiles/*"
	printout, err := netHelper.ExecCmd(
		client,
		w,
		"du -sh /var/opt/ericsson/amos/moshell_logfiles/*")

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//check printout
	for _, s := range printout {

		//skip, if the size is less than 1Gb
		if !strings.Contains(s, "G") {
			continue
		}

		//get dir and dir size
		var l []string = strings.Split(s, "G")
		var dir string = l[1]
		var s float64

		//convert size
		if size, err := strconv.ParseFloat(strings.Trim(l[0], " "), 32); err == nil {
			s = math.Floor(size)
		}

		//print report info
		if s < MoshellLogSizeThreshold {
			fmt.Fprintf(w, "\tok\t%vG\t%s\n", s, dir)
		} else {
			fmt.Fprintf(w, "\tnok\t%vG\t%s\n", s, dir)

			//test is failed
			Checks[name] = false

		}

	}

	//test passed
	if Checks[name] {
		fmt.Fprintln(w, "\tok\tthere is no big directories found")
	}

}

// CheckDBA runs OSS-RC's native database healthcheck
func CheckDBA(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckDBA"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run "su - sybase -c /ericsson/syb/util/dba_tools"
	printout, err := netHelper.ExecCmd(
		client,
		w,
		"su - sybase -c /ericsson/syb/util/dba_tools <<EOF\n13\n\n0\nEOF",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//check printout
	for _, s := range printout[42:53] {

		//split string to check name and result
		var l []string = strings.Split(s, ".")
		var check, result string = l[0], l[len(l)-1]

		//print report info
		if result == "OK!" {
			fmt.Fprintf(w, "\tok\t%s\n", check)
		} else {
			fmt.Fprintf(w, "\tnok\t%s\n", check)

			//test is failed
			Checks[name] = false

		}

	}

}

// CheckVrstDb checks mode and status of all versant databases
func CheckVrstDb(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckVrstDb"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run ""
	printout, err := netHelper.ExecCmd(
		client,
		w,
		"su - nmsadm -c /ericsson/versant/bin/vrsnt_admin.sh <<EOF\n1\n\n0\nEOF",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//check for the mode and status of all databases
	for i, s := range printout[48:54] {

		//split string to db and it's mode
		var l []string = strings.Fields(s)
		var db, mode string = l[0], l[2]

		//split string of db status and save it
		var status string = strings.Fields(printout[i+57])[2]

		//print report info
		if mode == "Multi-user" && status == "Online" {
			fmt.Fprintf(w, "\tok\t%s, %s - %s\n", mode, status, db)
		} else {
			fmt.Fprintf(w, "\tnok\t%s, %s - %s\n", mode, status, db)

			//test is failed
			Checks[name] = false

		}

	}

}

// CheckVrstDbSU checks space usage of all versant databases
func CheckVrstDbSU(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckVrstDbSU"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run ""
	printout, err := netHelper.ExecCmd(
		client,
		w,
		"su - nmsadm -c /ericsson/versant/bin/vrsnt_admin.sh <<EOF\n6\n\n0\nEOF",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//check for the mode and status of all databases
	for _, s := range printout[49:55] {

		//split string to get db and percent of db space usage
		var l []string = strings.Fields(s)
		var db string = l[0]
		su, _ := strconv.Atoi(strings.Trim(l[5], "%"))

		//print report info
		if su < VrstDbThreshold {
			fmt.Fprintf(w, "\tok\t%v%s\tspace usage of %s\n", su, "%", db)
		} else {
			fmt.Fprintf(w, "\tnok\t%v%s\tspace usage of %s\n", su, "%", db)

			//test is failed
			Checks[name] = false

		}

	}

}

// MonVrstDb checks if the new critical alarms if versant databases appeared
func MonVrstDb(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "MonVrstDb"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run ""
	printout, err := netHelper.ExecCmd(
		client,
		w,
		"su - nmsadm -c /ericsson/versant/bin/vrsnt_admin.sh <<EOF\n16\nall\nCRITICAL\nq\nq\n\n0\nEOF",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//create an empty array and append it with the strings of alarms dates
	var dates []string
	for _, s := range printout {

		//skip unusefull strings
		if len(s) < 6 {
			continue
		}

		//get the timestamp of alarms
		if s[:6] == "***** " {
			dates = append(dates, s)
		}

	}

	//print report info
	if dates[len(dates)-1] == TimestampOfLastVrstCriticalAlarm {
		fmt.Fprintln(w, "\tok\tno new critical alarms of versant databases found")
	} else {
		fmt.Fprintln(w, "\tnok\tnew critical alarm of versant databases appeared")

		//test is failed
		Checks[name] = false

	}

}

// CheckBsmAdjusts checks BSM adjust-jobs execution result on OSS-RC
func CheckBsmAdjusts(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckBsmAdjusts"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//get current date
	var now string = time.Now().Format(time.RFC3339)
	var d string = strings.ReplaceAll(strings.Split(now, "T")[0], "-", ":")

	//form cmd
	var cmd string = fmt.Sprintf(
		"grep \"%s\" /var/opt/ericsson/ncms/js/jobs/SCHED_*BSM*/0/*/data | grep TASK | awk '%s' | awk {'print $3\" \"$6'}",
		d,
		"NR%2 == 0",
	)

	//run cmd
	printout, err := netHelper.ExecCmd(client, w, cmd)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//print report info
	for _, s := range printout {

		//skip empty strings
		if len(s) == 0 {
			continue
		}

		//split string to fields bsc and adjust status
		var l []string = strings.Fields(s)
		var bsc, status string = l[0], l[1]

		//print report info
		if status == "COMPLETED" {
			fmt.Fprintf(w, "\tok\t%s\n", bsc)
		} else {
			fmt.Fprintf(w, "\tnok\t%s, BSM Adjust Job in status %s\n", bsc, status)

			//test is failed
			Checks[name] = false

		}

	}

}

// CheckCnaAdjusts checks CNA adjust-jobs execution result on OSS-RC
func CheckCnaAdjusts(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckCnaAdjusts"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//get current date
	var now string = time.Now().Format(time.RFC3339)
	var d string = strings.ReplaceAll(strings.Split(now, "T")[0], "-", ":")

	//form cmd
	var cmd string = fmt.Sprintf(
		"grep \"%s.*Job\" /var/opt/ericsson/ncms/js/jobs/*SCHED_*CNA*/0/*/data | awk '%s' | awk -F/ '{print $10\" \"$11}' | awk '{print $1\" \"$5}'",
		d,
		"NR%2 == 0",
	)

	//run cmd
	printout, err := netHelper.ExecCmd(client, w, cmd)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//print report info
	for _, s := range printout {

		//skip empty strings
		if len(s) == 0 {
			continue
		}

		//split string to fields bsc and adjust status
		var l []string = strings.Fields(s)
		var bsc, status string = strings.TrimPrefix(l[0], "SCHED_"), l[1]

		//print report info
		if status == "Completed" {
			fmt.Fprintf(w, "\tok\t%s\n", bsc)
		} else {
			fmt.Fprintf(w, "\tnok\t%s, CNA Adjust Job in status %s\n", bsc, status)

			//test is failed
			Checks[name] = false

		}

	}

}

// KillOldSessions checks users session and kills the old one
func KillOldSessions(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "KillOldSessions"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//get current date
	var now time.Time = time.Now()
	var d int = now.Day()
	var m string = now.Month().String()[:3]

	//form cmd
	var cmd string = fmt.Sprintf(
		"who -uH | perl -nE 'print \"$_\", unless /%s\\s+%v/;'",
		m,
		d,
	)

	//run cmd
	printout, err := netHelper.ExecCmd(client, w, cmd)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//print report info
	if len(printout) == 2 {
		fmt.Fprintln(w, "\tok\tno any old sessions")
		return
	}

	//check is failed
	Checks[name] = false

	//print old sessions info and get pid of them
	var pids []string
	for _, s := range printout[1:] {

		//skip empty strings
		if len(s) == 0 {
			continue
		}

		//split string to get session pid
		var l []string = strings.Fields(s)
		var pid string = l[len(l)-2]

		//add pid to the array of pids to kill
		pids = append(pids, pid)

		//print report info
		fmt.Fprintf(w, "\tnok\t%s\n", s)

	}

	//kill old sessions
	for _, pid := range pids {

		//kill old session
		_, err := netHelper.ExecCmd(
			client,
			w,
			fmt.Sprintf("kill -9 %s", pid),
		)

		//check command execution
		if err == nil {
			fmt.Fprintln(w, "\tok\tsession successfully killed")
		} else {
			fmt.Fprintln(w, "\tnok\tkilling of session is failed")
		}

	}

}

// CheckNetBackupClients checks connection between
// OMBS and NetBackup's clients
func CheckNetBackupClients(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckNetBackupClients"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run cmd to get the list of all clients
	printout, err := netHelper.ExecCmd(
		client,
		w,
		`egrep '192|172' /etc/hosts | awk '{print $2}' | grep -v 'alenmnas\b'`,
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//define an array of clients and add all required client
	var clients []string
	for _, s := range printout {

		//skip an empty strings
		if len(s) == 0 {
			continue
		}

		//skip clients which already in the list
		if common.IsStrInArr(clients, s) {
			continue
		}

		//add client to the list of clients
		clients = append(clients, s)

	}

	//check connection to client
	for _, host := range clients {

		//run cmd
		_, err := netHelper.ExecCmd(
			client,
			w,
			fmt.Sprintf("/usr/openv/netbackup/bin/admincmd/bptestbpcd -connect_timeout 5 -client %s", host),
		)

		//print report info
		if err == nil {
			fmt.Fprintf(w, "\tok\t%s connected\n", host)
		} else {
			fmt.Fprintf(w, "\tnok\t%s disconnected\n", host)

			//test is failed
			Checks[name] = false

		}

	}

}

// CheckBackupPoliciesSchedExec checks if the required backup policies in scheduler were executed
func CheckBackupPoliciesSchedExec(client *ssh.Client, host string, w io.Writer) {

	//init check name
	var name string = "CheckBackupPoliciesSchedExec"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//get the day of week and date
	var now time.Time = time.Now()
	var weekday string = now.Weekday().String()
	var date string = strings.Split(now.Format(time.RFC3339), "T")[0]

	//init policies scheduler
	var sched map[string]map[string]string = map[string]map[string]string{

		"almaty-oss-ombs": map[string]string{
			"ENIQ_STATS_MULTIBLADE_CORDINATOR_DATA_aleniq1bk": "Saturday",
			"ENIQ_STATS_MULTIBLADE_DATA_aleniq1enbk":          "Tuesday, Thursday, Saturday",
			"ENIQ_STATS_MULTIBLADE_DATA_aleniq1rdbk":          "Tuesday, Thursday, Saturday",
			"ENIQ_STATS_MULTIBLADE_DATA_aleniq1wrbk":          "Tuesday, Thursday, Saturday",
			"ENIQ_STATS_ONBLADE_RAW_aleniq1bk":                "Sunday",
			"ENIQ_STATS_ROOT_aleniq1bk":                       "Tuesday, Thursday, Saturday",
			"ENIQ_STATS_ROOT_aleniq1enbk":                     "Tuesday, Thursday, Saturday",
			"ENIQ_STATS_ROOT_aleniq1rdbk":                     "Tuesday, Thursday, Saturday",
			"ENIQ_STATS_ROOT_aleniq1wrbk":                     "Tuesday, Thursday, Saturday",
			"ENM_SCHEDULED_alenmmsbk":                         "Tuesday, Thursday, Saturday",
			"alenmombs_FILES":                                 "All",
			"alenmombs_Hot_Catalog":                           "All",
			"alomsas1bk_FILES":                                "All",
			"almbis1bk_windows":                               "All",
		},

		"astana-oss-ombs": map[string]string{
			"OSS_i386_DATA_MD_syb1bkup": "All",
			"OSS_i386_DATA_MS_ossbkup":  "All",
			"OSS_i386_ROOT_MD_syb1bkup": "All",
			"OSS_i386_ROOT_MS_ossbkup":  "All",
			"astinf1bl-bk_FILES":        "All",
			"astinf2bl-bk_FILES":        "All",
			"astmws-bk_FILES":           "All",
			"astnedss_FILES":            "All",
			"astombs1bl_FILES":          "All",
			"astombs1bl_Hot_Catalog":    "All",
			"astomsas_FILES":            "All",
			"astxts1bl-bk_FILES":        "All",
			"astxts2bl_FILES":           "All",
		},
	}

	//check each policy of host
	for policy, weekdays := range sched[host] {

		//skip, if the policy has not to be executed today
		if !strings.Contains(weekdays, weekday) && !strings.Contains(weekdays, "All") {
			continue
		}

		//define cmd
		var cmd string
		if host == "almaty-oss-ombs" {
			cmd = fmt.Sprintf("/ericsson/ombsl/bin/last_successful_backup.bsh -p %s", policy)
		} else {
			cmd = fmt.Sprintf("/ericsson/ombss/bin/last_successful_backup.bsh -p %s", policy)
		}

		//run cmd
		printout, err := netHelper.ExecCmd(client, w, cmd)

		//handle an error case
		if err != nil {
			CmdFailed(name, w)
			fmt.Fprintln(w)
			return
		}

		//split the information string
		var l []string = strings.Fields(printout[len(printout)-3])

		//print report info
		if l[2] == date {
			fmt.Fprintf(w, "\tok\tpolicy %s with type %s was succussfully executed on %s\n",
				l[7], l[6], l[4],
			)
		} else {
			fmt.Fprintf(w, "\tnok\t%sT%s - %sT%s %s %s\t%s\n",
				l[0], l[1], l[2], l[3], l[6], l[4], l[7],
			)

			//test is failed
			Checks[name] = false

		}

	}

}

// CheckHwResources checks status of ENM RAM/CPU
// required to run all assigned VM's on a Blade
func CheckHwResources(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckHwResources"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run cmd
	printout, err := netHelper.ExecCmd(
		client, w,
		"/opt/ericsson/enminst/bin/enm_healthcheck.sh --action hw_resources_healthcheck --verbose",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
	}

	//print report info
	for _, s := range printout {
		fmt.Fprintf(w, "\t%s\n", s)
	}

}

// CheckNas checks state of VA NAS in ENM
func CheckNas(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckNas"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run cmd
	printout, err := netHelper.ExecCmd(
		client, w,
		"/opt/ericsson/enminst/bin/enm_healthcheck.sh --action nas_healthcheck --verbose",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
	}

	//print report info
	for _, s := range printout {
		fmt.Fprintf(w, "\t%s\n", s)
	}

}

// CheckStoragePool checks the SAN StoragePool usage
func CheckStoragePool(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckStoragePool"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run cmd
	printout, err := netHelper.ExecCmd(
		client, w,
		"/opt/ericsson/enminst/bin/enm_healthcheck.sh --action storagepool_healthcheck --verbose",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
	}

	//print report info
	for _, s := range printout {
		fmt.Fprintf(w, "\t%s\n", s)
	}

}

// CheckStaleMount checks for stale mounts on MS and Peer Nodes
func CheckStaleMount(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckStaleMount"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run cmd
	printout, err := netHelper.ExecCmd(
		client, w,
		"/opt/ericsson/enminst/bin/enm_healthcheck.sh --action stale_mount_healthcheck --verbose",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
	}

	//print report info
	for _, s := range printout {
		fmt.Fprintf(w, "\t%s\n", s)
	}

}

// CheckNodeFs checks Filesystem Usage on MS, NAS and Peer Nodes
func CheckNodeFs(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckNodeFs"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run cmd
	printout, err := netHelper.ExecCmd(
		client, w,
		"/opt/ericsson/enminst/bin/enm_healthcheck.sh --action node_fs_healthcheck --verbose",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
	}

	//print report info
	for _, s := range printout {
		fmt.Fprintf(w, "\t%s\n", s)
	}

}

// CheckSystemService checks status of key lsb services on each Blade
func CheckSystemService(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckSystemService"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run cmd
	printout, err := netHelper.ExecCmd(
		client, w,
		"/opt/ericsson/enminst/bin/enm_healthcheck.sh --action system_service_healthcheck --verbose",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
	}

	//print report info
	for _, s := range printout {
		fmt.Fprintf(w, "\t%s\n", s)
	}

}

// CheckVcsCluster checks the state of the VCS clusters on the deployment
func CheckVcsCluster(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckVcsCluster"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run cmd
	printout, err := netHelper.ExecCmd(
		client, w,
		"/opt/ericsson/enminst/bin/enm_healthcheck.sh --action vcs_cluster_healthcheck --verbose",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
	}

	//print report info
	for _, s := range printout {
		fmt.Fprintf(w, "\t%s\n", s)
	}

}

// CheckVcsLltHeartbeat checks state of VCS llt heartbeat network interfaces on the deployment
func CheckVcsLltHeartbeat(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckVcsLltHeartbeat"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run cmd
	printout, err := netHelper.ExecCmd(
		client, w,
		"/opt/ericsson/enminst/bin/enm_healthcheck.sh --action vcs_llt_heartbeat_healthcheck --verbose",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
	}

	//print report info
	for _, s := range printout {
		fmt.Fprintf(w, "\t%s\n", s)
	}

}

// CheckVcsServiceGroup checks state of VCS service groups on the deployment
func CheckVcsServiceGroup(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckVcsServiceGroup"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run cmd
	printout, err := netHelper.ExecCmd(
		client, w,
		"/opt/ericsson/enminst/bin/enm_healthcheck.sh --action vcs_service_group_healthcheck --verbose",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
	}

	//print report info
	for _, s := range printout {
		fmt.Fprintf(w, "\t%s\n", s)
	}

}

// CheckConsul checks status of consul cluster
func CheckConsul(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckConsul"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run cmd
	printout, err := netHelper.ExecCmd(
		client, w,
		"/opt/ericsson/enminst/bin/enm_healthcheck.sh --action consul_healthcheck --verbose",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
	}

	//print report infor
	for _, s := range printout {
		fmt.Fprintf(w, "\t%s\n", s)
	}

}

// CheckMultipathActive checks paths to disks on DB nodes are all accessible
func CheckMultipathActive(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckMultipathActive"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run cmd
	printout, err := netHelper.ExecCmd(
		client, w,
		"/opt/ericsson/enminst/bin/enm_healthcheck.sh --action multipath_active_healthcheck --verbose",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
	}

	//print report infor
	for _, s := range printout {
		fmt.Fprintf(w, "\t%s\n", s)
	}

}

// CheckPuppetEnabled checks Puppet is enabled on all nodes
func CheckPuppetEnabled(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckPuppetEnabled"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run cmd
	printout, err := netHelper.ExecCmd(
		client, w,
		"/opt/ericsson/enminst/bin/enm_healthcheck.sh --action puppet_enabled_healthcheck --verbose",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
	}

	//print report info
	for _, s := range printout {
		fmt.Fprintf(w, "\t%s\n", s)
	}

}

// CheckSanAlert checks if there are critical alerts on the SAN
func CheckSanAlert(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckSanAlert"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run cmd
	printout, err := netHelper.ExecCmd(
		client, w,
		"/opt/ericsson/enminst/bin/enm_healthcheck.sh --action san_alert_healthcheck --verbose",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
	}

	//print report info
	for _, s := range printout {
		fmt.Fprintf(w, "\t%s\n", s)
	}

}

// CheckMdt checks MDT status
func CheckMdt(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckMdt"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run cmd
	printout, err := netHelper.ExecCmd(
		client, w,
		"/opt/ericsson/enminst/bin/enm_healthcheck.sh --action mdt_healthcheck --verbose",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
	}

	//print report info
	for _, s := range printout {
		fmt.Fprintf(w, "\t%s\n", s)
	}

}

// CheckZfsPoolStatus checks the status of ZFS pool file systems
func CheckZfsPoolStatus(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckZfsPoolStatus"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run cmd
	printout, err := netHelper.ExecCmd(
		client, w,
		"/usr/sbin/zpool list",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
	}

	//check printout
	for _, s := range printout[1:4] {

		//split string to get fsname and status
		var l []string = strings.Fields(s)
		var fsname string = l[0]
		var status string = l[6]

		//print report info
		if status == "ONLINE" {
			fmt.Fprintf(w, "\tok\t%s - %s\n", status, fsname)
		} else {
			fmt.Fprintf(w, "\tnok\t%s - %s\n", status, fsname)

			//test is failed
			Checks[name] = false

		}

	}

}

// CheckZfsPoolSU checks ZFS pool space usage
func CheckZfsPoolSU(client *ssh.Client, host string, w io.Writer) {

	//init check name
	var name string = "CheckZfsPoolSU"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//init map of normal hosts filesystems space usage
	var thresholds map[string]map[string]int = map[string]map[string]int{

		"eniq-coordinator": map[string]int{
			"eniq_sp_1":              50, //20
			"rpool":                  70, //54
			"stats_coordinator_pool": 70, //50
		},

		"eniq-engine": map[string]int{
			"eniq_sp_1":         50, //15
			"rpool":             70, //52
			"stats_engine_pool": 5,  //0
		},

		"eniq-reader": map[string]int{
			"eniq_sp_1":      50, //14
			"rpool":          50, //24
			"stats_iqr_pool": 20, //4
		},

		"eniq-writer": map[string]int{
			"eniq_sp_1":      50, //14
			"rpool":          50, //24
			"stats_iqr_pool": 20, //4
		},
	}

	//run cmd
	printout, err := netHelper.ExecCmd(
		client, w,
		"/usr/sbin/zpool list",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
	}

	//check printout
	for _, s := range printout[1:4] {

		//split string to get fsname and space usage
		var l []string = strings.Fields(s)
		var fsname string = l[0]
		su, err := strconv.Atoi(strings.TrimRight(l[4], "%"))

		//handle an error case
		if err != nil {
			CmdFailed(name, w)
			fmt.Fprintln(w)
		}

		//print report info
		if su <= thresholds[host][fsname] {
			fmt.Fprintf(w, "\tok\t%v%s\t%s\n", su, "%", fsname)
		} else {
			fmt.Fprintf(w, "\tnok\t%v%s\t%s\n", su, "%", fsname)

			//test is failed
			Checks[name] = false

		}

	}

}

// CheckZfsPoolErrors checks if there are any error in ZFS pool
func CheckZfsPoolErrors(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckZfsPoolErrors"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run cmd
	printout, err := netHelper.ExecCmd(
		client, w,
		"/usr/sbin/zpool status | egrep 'pool:|errors'",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
	}

	//check printout
	for i, s := range printout {

		//skip empty strings
		if len(s) == 0 {
			continue
		}

		//find fsname
		if strings.Contains(s, "pool:") {

			//get fsname
			var fsname string = strings.Fields(s)[1]

			//check errors
			var errs string = strings.Split(printout[i+1], ": ")[1]

			//print report info
			if errs == "No known data errors" {
				fmt.Fprintf(w, "\tok\tno errors\t%s\n", fsname)
			} else {
				fmt.Fprintf(w, "\tnok\t%s - %s\n", fsname, errs)

				//test is failed
				Checks[name] = false

			}

		}

	}

}

// CheckHostUptime checks host uptime to ensure that it was not restarted
func CheckHostUptime(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckHostUptime"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run cmd
	printout, err := netHelper.ExecCmd(client, w, "uptime")

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//get the munber of day the server is up
	days, err := strconv.Atoi(strings.Fields(printout[0])[2])

	//print report info
	if days > UptimeThreshold {
		fmt.Fprintf(w, "\tok\tup %v day(s)\n", days)
	} else {
		fmt.Fprintf(w, "\tnok\tup %v day(s). Looks like the server was restarted\n", days)

		//test is failed
		Checks[name] = false

	}

}

// FindParsedInKnown checks that all parsed entries of ETLC are known already
func FindParsedInKnown(have, must map[string]int, w io.Writer) bool {

	//init check name
	var name string = "FindParsedInKnown"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//print check header
	fmt.Fprintln(w, "\n->>> check, that all parsed entries are known already")

	//compare
	for k := range have {

		//get entry
		_, ok := must[k]

		//is new table found
		if ok {
			fmt.Fprintf(w, "\tok\ttable is known\t%s\n", k)
		} else {
			fmt.Fprintf(w, "\tnok\ttable is unknown\t%s\n", k)

			//test is failed
			Checks[name] = false

		}

	}

	//return result
	return Checks[name]

}

// FindKnownInParsed checks that all known entries of ETLC are found in the today's log
func FindKnownInParsed(have, must map[string]int, w io.Writer) bool {

	//init check name
	var name string = "FindKnownInParsed"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//print check header
	fmt.Fprintln(w, "\n->>> check, that all known entries are found in the log")

	//compare
	for k := range must {

		//get entry
		_, ok := have[k]

		//print report info
		if ok {
			fmt.Fprintf(w, "\tok\texists in today's log\t%s\n", k)
		} else {
			fmt.Fprintf(w, "\tnok\tabsent in today's log\t%s\n", k)

			//test is failed
			Checks[name] = false

		}

	}

	//return result
	return Checks[name]

}

// CompareNumParsed compares the number of parsed entries of ETLC with required one
func CompareNumParsed(have, must map[string]int, w io.Writer) bool {

	//init check name
	var name string = "CompareNumParsed"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//print check header
	fmt.Fprintln(w, "\n->>> compares the number of parsed entries with required one")
	fmt.Fprintln(w, "\t\thave/must\t\ttable")

	//compare
	for k, v := range must {

		//get entry
		vh, ok := have[k]

		//set the value of parsed entries if the there are no any entries
		if !ok {
			vh = 0
		}

		//print report info
		if vh >= v {
			fmt.Fprintf(w, "\tok\t%v/%v\t\t%s\n", vh, v, k)
		} else {
			fmt.Fprintf(w, "\tnok\t%v/%v\t\t%s\n", vh, v, k)

			//test is failed
			Checks[name] = false

		}

	}

	//return result
	return Checks[name]

}

// DeepCheckETLC performs deep analise of activities in ENIQ ETLC Monitoring
// Applicable for eniq-engine only
func DeepCheckETLC(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "DeepCheckETLC"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//init map, keys are tables name, values are number of tables entries in the log
	var have map[string]int = make(map[string]int)

	//init map of tables entries
	var must map[string]int = map[string]int{
		"DIM_E_LTE_SITE-eniq_oss_2":            1,
		"DIM_E_GRAN_BTS-eniq_oss_2":            1,
		"DIM_E_GRAN_LBG-eniq_oss_2":            1,
		"DIM_E_GRAN_SITE-eniq_oss_2":           1,
		"DC_E_RADIONODE_MIXED-eniq_oss_2":      25,
		"DIM_E_GRAN_STGASSOCIATION-eniq_oss_2": 1,
		"DC_E_CNAXE_MSCCL_APG-eniq_oss_2":      25,
		"DIM_E_GRAN_NW-eniq_oss_2":             1,
		"DIM_E_CN_SITE-eniq_oss_2":             1,
		"DIM_RAN_BASE_SITE-eniq_oss_2":         1,
		"DC_E_RBSG2-eniq_oss_2":                25,
		"DIM_RAN_BASE_RBS-eniq_oss_2":          1,
		"DIM_E_LTE_ERBS-eniq_oss_2":            1,
		"DIM_E_GRAN_AS-eniq_oss_2":             1,
		"DIM_E_CN_MSCCL-eniq_oss_2":            1,
		"DIM_E_CN_HADDR-eniq_oss_2":            25,
		"DC_E_BSS_APG-eniq_oss_2":              25,
		"DIM_RAN_BASE_RNC-eniq_oss_2":          1,
		"DC_E_CNAXE_HLRVLRSUB-eniq_oss_2":      7,
		"DIM_E_CN_AXE-eniq_oss_2":              1,
		"DC_E_RBS-eniq_oss_2":                  25,
		"DC_E_CNAXE_APG-eniq_oss_2":            7,
		"DIM_E_GRAN_CELL-eniq_oss_2":           1,
		"DIM_E_GRAN_SCGR-eniq_oss_2":           1,
		"DIM_E_GRAN_TG-eniq_oss_2":             1,
		"DC_E_BTSG2-eniq_oss_2":                25,
		"DC_E_RNC-eniq_oss_2":                  25,
		"DIM_E_GRAN_MCTR-eniq_oss_2":           1,
		"DIM_E_CN_MSCCLMF_AS-eniq_oss_2":       1,
		"DC_E_NR_RAT-eniq_oss_3":               25,
		"DC_E_BSS_APG-eniq_oss_3":              25,
		"DC_E_ERBSG2-eniq_oss_3":               25,
		"DIM_E_CN_AXE-eniq_oss_3":              1,
		"DIM_E_GRAN_TG-eniq_oss_3":             1,
		"DC_E_CNAXE_APG-eniq_oss_3":            25,
		"DC_E_RNC-eniq_oss_3":                  25,
		"DC_E_MGW-eniq_oss_3":                  36,
		"DIM_E_GRAN_NW-eniq_oss_3":             1,
		"DIM_E_LTE_NR-eniq_oss_3":              1,
		"DIM_E_IPRAN_TWAMPSESSIONS-eniq_oss_3": 1,
		"DC_E_ERBS-eniq_oss_3":                 25,
		"DIM_RAN_BASE_RNC-eniq_oss_3":          2,
		"DIM_E_GRAN_MCTR-eniq_oss_3":           1,
		"DIM_E_GRAN_SCGR-eniq_oss_3":           1,
		"DIM_E_GRAN_STGASSOCIATION-eniq_oss_3": 1,
		"DC_E_RBS-eniq_oss_3":                  25,
		"DIM_E_GRAN_CELL-eniq_oss_3":           1,
		"DIM_E_GRAN_LBG-eniq_oss_3":            1,
		"DIM_E_CN_MGW-eniq_oss_3":              1,
		"DC_E_RBSG2-eniq_oss_3":                25,
		"DIM_E_GRAN_AS-eniq_oss_3":             1,
		"DIM_RAN_BASE_RBS-eniq_oss_3":          1,
		"DC_E_RADIONODE_MIXED-eniq_oss_3":      25,
		"DC_E_BTSG2-eniq_oss_3":                25,
		"DIM_E_GRAN_BTS-eniq_oss_3":            1,
		"DIM_E_LTE_ERBS-eniq_oss_3":            1,
		"DIM_E_CN_CN-eniq_oss_3":               1,
	}

	//get current date
	var now string = time.Now().Format(time.RFC3339)
	var d string = strings.ReplaceAll(strings.Split(now, "T")[0], "-", "_")

	//run cmd for oss
	printout, err := netHelper.ExecCmd(
		client,
		w,
		"grep -i parsed /eniq/log/sw_log/engine/engine-"+d+".log",
	)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		return
	}

	//check printout and fill in map of parsed entries
	for _, s := range printout {

		//skip empty strings
		if len(s) == 0 {
			continue
		}

		//split string to fields and get field with the table name
		var f string = strings.Fields(s)[4]

		//split f to get table name
		var table string = strings.TrimLeft(strings.Split(f, ".")[1], "INTF_")

		//add to map
		counter, ok := have[table]
		if ok {
			have[table] = counter + 1
		} else {
			have[table] = 1
		}
	}

	//check, that all parsed entries are known already
	if !FindParsedInKnown(have, must, w) {
		Checks[name] = false
	}

	//check, that all known entries are found in the log
	if !FindKnownInParsed(have, must, w) {
		Checks[name] = false
	}

	//compare the number of parsed entries of ETLC with required one
	if !CompareNumParsed(have, must, w) {
		Checks[name] = false
	}

}

// CheckSrvs checks services states,
// all required services should be online
func CheckSrvs(client *ssh.Client, host string, w io.Writer) {

	//init check name
	var name string = "CheckSrvs"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//init map of required "svcs" cmd
	var srvs map[string][]string = map[string][]string{
		"eniq-coordinator": []string{
			"svc:/storage/NASd:default",
			"svc:/licensing/sentinel:default",
			"svc:/eniq/esm:default",
			"svc:/eniq/rmiregistry:default",
			"svc:/eniq/licmgr:default",
			"svc:/eniq/connectd:default",
			"svc:/eniq/repdb:default",
			"svc:/eniq/dwhdb:default",
			"svc:/eniq/webserver:default",
			"svc:/system/scheduler:default",
			"svc:/application/cups/scheduler:default",
			"svc:/eniq/scheduler:default",
			"svc:/eniq/sim:default",
			"svc:/ericsson/eric_monitor/ddc:default",
			"svc:/eniq/roll-snap:default",
			"svc:/storage/NASd:default",
			"svc:/milestone/NAS-online:default",
		},

		"eniq-engine": []string{
			"svc:/storage/NASd:default",
			"svc:/eniq/esm:default",
			"svc:/eniq/rmiregistry:default",
			"svc:/eniq/connectd:default",
			"svc:/eniq/engine:default",
			"svc:/ericsson/eric_monitor/ddc:default",
			"svc:/eniq/roll-snap:default",
		},

		"eniq-reader": []string{
			"svc:/eniq/esm:default",
			"svc:/eniq/dwh_reader:default",
			"svc:/eniq/roll-snap:default",
			"svc:/ericsson/eric_monitor/ddc:default",
		},
		"eniq-writer": []string{
			"svc:/eniq/esm:default",
			"svc:/eniq/dwh_reader:default",
			"svc:/eniq/roll-snap:default",
			"svc:/ericsson/eric_monitor/ddc:default",
		},
	}

	//run cmd for each service what must be available on certain host
	for _, srv := range srvs[host] {

		//run cmd
		printout, err := netHelper.ExecCmd(
			client,
			w,
			fmt.Sprintf("svcs -l %s", srv),
		)

		//handle an error case
		if err != nil {
			CmdFailed(name, w)
			continue
		}

		//get service description
		var desc string = strings.Join(strings.Fields(printout[1])[1:], " ")

		//get status and state
		var status string = strings.Fields(printout[2])[1]
		var state string = strings.Fields(printout[3])[1]

		//print report info
		if state == "online" && status == "true" {
			fmt.Fprintf(w, "\tok\t%s/%s\t%s\n", status, state, desc)
		} else {
			fmt.Fprintf(w, "\tnok\t%s/%s\t%s\n", status, state, desc)

			//test is failed
			Checks[name] = false

		}

	}

}

// CheckSrvsUptime checks each service which must be available on certain host
// to ensure that the service start time was not updated
func CheckSrvsUptime(client *ssh.Client, host string, w io.Writer) {

	//init check name
	var name string = "CheckSrvsUptime"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//init map of required "svcs" cmd
	var srvs map[string][]string = map[string][]string{
		"eniq-coordinator": []string{
			"svc:/storage/NASd:default",
			"svc:/licensing/sentinel:default",
			"svc:/eniq/esm:default",
			"svc:/eniq/rmiregistry:default",
			"svc:/eniq/licmgr:default",
			"svc:/eniq/connectd:default",
			"svc:/eniq/repdb:default",
			"svc:/eniq/dwhdb:default",
			"svc:/eniq/webserver:default",
			"svc:/system/scheduler:default",
			"svc:/application/cups/scheduler:default",
			"svc:/eniq/scheduler:default",
			"svc:/eniq/sim:default",
			"svc:/eniq/roll-snap:default",
			"svc:/storage/NASd:default",
			"svc:/milestone/NAS-online:default",
		},

		"eniq-engine": []string{
			"svc:/storage/NASd:default",
			"svc:/eniq/esm:default",
			"svc:/eniq/rmiregistry:default",
			"svc:/eniq/connectd:default",
			"svc:/eniq/engine:default",
			"svc:/eniq/roll-snap:default",
		},

		"eniq-reader": []string{
			"svc:/eniq/esm:default",
			"svc:/eniq/dwh_reader:default",
			"svc:/eniq/roll-snap:default",
		},
		"eniq-writer": []string{
			"svc:/eniq/esm:default",
			"svc:/eniq/dwh_reader:default",
			"svc:/eniq/roll-snap:default",
		},
	}

	//define history filename
	var history string = filepath.Join("var", host+".srvs")

	//read previously saved services start time and build the map
	var prevTime map[string]string = make(map[string]string)
	for _, s := range common.GetFileStrings(history) {

		//skip an empty strings
		if len(s) == 0 {
			continue
		}

		//split string
		var l []string = strings.Fields(s)

		//define service and start time
		var srv string = l[0]
		var time string = strings.Join(l[1:], " ")

		//build map
		prevTime[srv] = time

	}

	//get writer to save current services state
	wSrvs, err := common.GetWriter(history)
	if err != nil {
		fmt.Fprintf(w, "\tnok\t%s\n", err.Error())
	}

	//run cmd for each service what must be available on certain host
	//and check that the service start time was not updated
	for _, srv := range srvs[host] {

		//run cmd
		printout, err := netHelper.ExecCmd(
			client,
			w,
			fmt.Sprintf("svcs -l %s", srv),
		)

		//handle an error case
		if err != nil {
			CmdFailed(name, w)
			continue
		}

		//get service description
		var desc string = strings.Join(strings.Fields(printout[1])[1:], " ")

		//get state time
		var time string = strings.Join(strings.Fields(printout[5])[1:], " ")

		//print report info
		if time == prevTime[srv] {
			fmt.Fprintf(w, "\tok\t%s == %s\t%s\n", prevTime[srv], time, desc)
		} else {
			fmt.Fprintf(w, "\tnok\t%s => %s\t%s\n", prevTime[srv], time, desc)

			//test is fail
			Checks[name] = false

		}

		//save current services state
		fmt.Fprintln(wSrvs, srv, time)

	}

	//right writer closing
	common.CloseWriter(wSrvs)

}

// CheckMountingOk checks if all required disk are mounted properly
func CheckMountingOk(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckMountingOk"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//run cmd
	_, err := netHelper.ExecCmd(client, w, "df -kh")

	//handle an error case
	if err == nil {
		fmt.Fprintln(w, "\tok\tall disks mounted properly")
	} else {
		fmt.Fprintln(w, "\tnok\terror in disks mounting")

		//test is failed
		Checks[name] = false

	}

}

// CheckBashrc checks /etc/bashrc file for custom settings
func CheckBashrc(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckBashrc"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//init cmd
	var cmd string = `for i in $(cat /etc/hosts | egrep "scp-.-(amos|scripting)\b" | awk '{print $2}'); do ssh -i /root/.ssh/vm_private_key cloud-user@${i} 'grep "if.*nodesAliases" /etc/bashrc'; done`

	//run cmd
	printout, err := netHelper.ExecCmd(client, w, cmd)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//print report info
	if len(printout) == 5 {
		fmt.Fprintln(w, "\tok\tcustom settings are found in the bashrc")
	} else {
		fmt.Fprintln(w, "\tnok\tcustom settings not found in the bashrc")

		//test if failed
		Checks[name] = false

	}

}

// CheckNodesFilesUpdate checks that ipdatabase and nodesAliases files are up to date
func CheckNodesFilesUpdate(client *ssh.Client, w io.Writer) {

	//init check name
	var name string = "CheckNodesFilesUpdate"

	//before check is executed lets say that it would passed successfully
	Checks[name] = true

	//init today's date
	var d string = strings.Split(time.Now().Format(time.RFC3339), "T")[0]

	//init an array of files to check
	var files []string = []string{"nodesAliases", "ipdatabase"}

	//init cmd
	var cmd string = `for i in $(cat /etc/hosts | egrep "scp-.-(amos|scripting)\b" | awk '{print $2}'); do ssh -i /root/.ssh/vm_private_key cloud-user@${i} 'ls -l --time-style=long-iso /home/shared/common/sitefiles/ | grep -v backup' ; done`

	//run cmd
	printout, err := netHelper.ExecCmd(client, w, cmd)

	//handle an error case
	if err != nil {
		CmdFailed(name, w)
		fmt.Fprintln(w)
		return
	}

	//check printout
	for _, file := range files {

		//init counter for founded up to date files
		var counter int

		//search file
		for _, s := range printout {
			if strings.Contains(s, file) && strings.Contains(s, d) {
				//increase counter
				counter += 1
			}
		}

		//print report info
		if counter == 4 {
			fmt.Fprintf(w, "\tok\tfound %d %s of %s\n", counter, file, d)
		} else {
			fmt.Fprintf(w, "\tnok\tfound %d %s of %s\n", counter, file, d)

			//test if failed
			Checks[name] = false

		}

	}

}
