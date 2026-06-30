// Command mayfly is the Mayfly zero-trust SSH access CLI.
//
// Milestone 011A establishes the reusable client foundation (OAuth provider
// framework, client context, credential storage, HTTP client, developer mode,
// SSH diagnostics, layered configuration). Login and SSH commands are added in
// later milestones on top of this foundation.
package main

import "github.com/mayfly-ssh/mayfly-cli/cmd"

func main() {
	cmd.Execute()
}
