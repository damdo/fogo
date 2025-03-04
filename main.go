package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

const (
	logo = `
   _               
 _|_ _   _   _     
  | (_) (_| (_)  (Fixer of OpenShift GO vulnerabilities)
         _|        


`
	modeFix   = "fix"
	modeCheck = "check"
)

var (
	vulnerabilityRef string
	mode             string
	defaultBranch    string
	ocpRemote        string
	ocpBegin         int
	ocpEnd           int
)

type Finding struct {
	OSV          string `json:"osv"`
	Module       string `json:"module"`
	FixedVersion string `json:"fixed_version"`
}

func main() {
	fmt.Print(logo)

	flag.StringVar(&mode, "mode", "fix", "working mode. Default: fix. Examples: fix (proposes fixes for the matching vulnerabilities), check (only checks for matching vulnerabilites and exits)")
	flag.StringVar(&vulnerabilityRef, "vuln", "", "vulnerability reference. CVE and GO vuln id references are supported. Examples: CVE-2025-22868 or GO-2025-3488")
	flag.StringVar(&defaultBranch, "default-branch", "main", "default branch for the repository")
	flag.StringVar(&ocpRemote, "remote", "ocp", "remote name that points to the official openshift remote repository")
	flag.IntVar(&ocpBegin, "begin", 12, "earlies OpenShift minor version release branch to check for vulnerabilities. Examples: 12 (for release-4.12). Default: 12")
	flag.IntVar(&ocpEnd, "end", 19, "latest OpenShift minor version release branch to check for vulnerabilities. Examples: 19 (for release-4.19). Default: 19")
	flag.Parse()

	branchPrefix := "release-4."

	if err := checkDependencies([]string{"jq", "govulncheck", "git"}); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	goID, err := getGoID(vulnerabilityRef)
	if err != nil {
		fmt.Printf("unable to find matching Go vuln ID for %s: %v\n", vulnerabilityRef, err)
		os.Exit(1)
	}

	fmt.Printf("provided %s maps to %s\n", vulnerabilityRef, goID)
	fmt.Printf("now scanning for vulnerability %q in release-4.%d -> release-4.%d\n", goID, ocpEnd, ocpBegin)

	// Loop through release branches from newest to oldest.
	for i := ocpEnd; i >= ocpBegin; i-- {
		branch := branchPrefix + strconv.Itoa(i)
		ref := ocpRemote + "/" + branch

		fmt.Println("---------------->")
		fmt.Printf("fetching ref: %s\n", ref)
		if err := execCommand(true, "git", "fetch", ocpRemote, branch); err != nil {
			fmt.Printf("Error: Failed to fetch %s: %v. is the official openshift git remote configured for the repository?\n", ref, err)
			continue
		}

		fmt.Printf("switching to ref: %s\n", ref)
		if err := execCommand(true, "git", "checkout", ref); err != nil {
			fmt.Printf("Error: Failed to checkout %s: %v\n", ref, err)
			continue
		}

		finding, err := findVulnerabilitiesWithJq(goID)
		if err != nil {
			fmt.Printf("Error running govulncheck: %v\n", err)
			continue
		}

		if finding == nil {
			fmt.Printf("no matching vulnerability found in %s\n", ref)
			continue
		}

		fmt.Printf("vulnerability matching %s found in %s:\n", goID, ref)

		jsonOutput, _ := json.MarshalIndent(finding, "", "  ")
		fmt.Println(string(jsonOutput))

		if modeFix != mode {
			continue
		}

		if !promptYesNo("do you want to fix it?") {
			continue
		}

		fmt.Println("OK, fixing matching vulnerability..")

		fixedPkg := fmt.Sprintf("%s@%s", finding.Module, finding.FixedVersion)
		fmt.Printf("running 'go get %s'\n", fixedPkg)
		if err := execCommand(false, "go", "get", fixedPkg); err != nil {
			fmt.Printf("Error running go get: %v\n", err)
			continue
		}
		if err := execCommand(false, "go", "mod", "tidy"); err != nil {
			fmt.Printf("Error running go mod tidy: %v\n", err)
		}
		if err := execCommand(false, "go", "mod", "vendor"); err != nil {
			fmt.Printf("Error running go mod vendor: %v\n", err)
		}

		status, err := getGitStatus()
		if err != nil {
			fmt.Printf("Error getting git status: %v\n", err)
			continue
		}

		if status == "" {
			fmt.Println("no changes detected")
			continue
		}

		fmt.Println("changes detected")
		execCommand(false, "git", "status")

		if promptYesNo("do you want to see the diff?") {
			execCommand(false, "git", "diff")
		}

		newBranchName := "bump-" + strings.ReplaceAll(strings.ReplaceAll(fixedPkg, "/", "-"), "@", "-")

		if promptYesNo("changes detected do you want to add/commit them?") {
			execCommand(true, "git", "switch", "-c", newBranchName)
			execCommand(false, "git", "add", ".")
			execCommand(false, "git", "commit", "-m", "bump to "+fixedPkg)

			if promptYesNo("do you want to push the new commit to origin?") {
				execCommand(false, "git", "push", "origin", newBranchName)
			}
		} else {
			fmt.Println("exiting for manual changes")
			os.Exit(0)
		}

		fmt.Println("----------------")
	}

	fmt.Println("switching back to the default branch")

	if err := execCommand(true, "git", "switch", defaultBranch); err != nil {
		fmt.Printf("failed to switch back to the default branch %q: %v", defaultBranch, err)
		os.Exit(1)
	}

	fmt.Println("all done")
}

// getGoID searches the Go package site for the Go vuln ID associated with a vulnID.
func getGoID(vulnID string) (string, error) {
	if strings.HasPrefix(vulnID, "GO-") {
		// vulnID is already a GO vuln ID.
		return vulnID, nil
	}

	if !strings.HasPrefix(vulnID, "CVE-") {
		return "", fmt.Errorf("unsupported vulnerability reference: %q", vulnID)
	}

	resp, err := http.Get("https://pkg.go.dev/search?q=" + vulnID)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	re := regexp.MustCompile(`GO-[0-9]*-[0-9]*`)
	matches := re.FindString(string(body))
	if matches == "" {
		return "", fmt.Errorf("no OSV ID found for %s", vulnID)
	}

	return matches, nil
}

// findVulnerabilitiesWithJq runs govulncheck and uses jq to extract vulnerabilities matching the OSV ID
func findVulnerabilitiesWithJq(osv string) (*Finding, error) {
	govulnCmd := exec.Command("govulncheck", "-json", "./...")

	var govulnOutput bytes.Buffer
	govulnCmd.Stdout = &govulnOutput
	govulnCmd.Stderr = os.Stderr

	if err := govulnCmd.Run(); err != nil {
		return nil, fmt.Errorf("govulncheck failed: %v", err)
	}

	// Now pass the govulncheck output through a sequence of jq commands to return a single matching Finding.
	jqFilterCmd := exec.Command("sh", "-c",
		fmt.Sprintf(`jq '[.finding | {osv: .osv, module: .trace[0].module, fixed_version: .fixed_version}]'`+
			` | jq -s 'flatten(1)'`+
			` | jq -s '.[] |= unique'`+
			` | jq '.[0]'`+
			` | jq '.[] | select(.osv == "%s")'`, osv))

	var jqOutput bytes.Buffer
	jqFilterCmd.Stdin = bytes.NewBuffer(govulnOutput.Bytes())
	jqFilterCmd.Stdout = &jqOutput
	jqFilterCmd.Stderr = os.Stderr

	if err := jqFilterCmd.Run(); err != nil {
		return nil, fmt.Errorf("jq processing failed: %v", err)
	}

	// If no output, return empty finding.
	if jqOutput.Len() == 0 {
		return nil, nil
	}
	out := jqOutput.Bytes()

	var finding Finding
	if err := json.Unmarshal(out, &finding); err != nil {
		return nil, fmt.Errorf("failed to parse jq output: %v", err)
	}

	return &finding, nil
}

// execCommand executes a shell command and captures its output
func execCommand(silence bool, command string, args ...string) error {
	cmd := exec.Command(command, args...)

	if !silence {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	return cmd.Run()
}

// getGitStatus returns the output of git status --porcelain.
func getGitStatus() (string, error) {
	cmd := exec.Command("git", "status", "--porcelain")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// promptYesNo asks the user for a yes/no response.
func promptYesNo(question string) bool {
	fmt.Printf("%s [y/N] ", question)
	var response string
	fmt.Scanln(&response)
	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}

// Check if a binary is installed.
func isBinaryInstalled(binaryName string) bool {
	_, err := exec.LookPath(binaryName)
	return err == nil
}

// checkDependencies checks a list of dependencies is installed on the system.
func checkDependencies(deps []string) error {
	notFound := []string{}
	for _, binary := range deps {
		if !isBinaryInstalled(binary) {
			notFound = append(notFound, binary)
		}
	}

	if len(notFound) > 0 {
		return fmt.Errorf("unable to find the following dependency programs: %v, please install them", notFound)
	}

	return nil
}
