// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package command

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hashicorp/cli"
	"github.com/hashicorp/go-secure-stdlib/password"
	"github.com/hashicorp/vault/api"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*OperatorVerifyQuorumCommand)(nil)
	_ cli.CommandAutocomplete = (*OperatorVerifyQuorumCommand)(nil)
)

type OperatorVerifyQuorumCommand struct {
	*BaseCommand

	flagInit   bool
	flagCancel bool
	flagStatus bool
	flagNonce  string

	testStdin io.Reader // for tests
}

func (c *OperatorVerifyQuorumCommand) Synopsis() string {
	return "Practice combining a quorum of share holders"
}

func (c *OperatorVerifyQuorumCommand) Help() string {
	helpText := `
Usage: vault operator verify [options] -init
       vault operator verify [options] [-nonce=... KEY]
       vault operator verify [options] -status
       vault operator verify [options] -cancel

  Practice combining a quorum of share holders.

  This command is unusual, as it is effectively four separate subcommands,
  selected via the options -init, -status, -cancel, or the absence of any 
  of the previous three options (which selects the provide a key share" form).

  Form 1 (-init) - Start a verification:

    	$ vault operator verify -init

  Form 2 (no option) - Enter an unseal key to progress the verification:

    In the sub-form intended for interactive use, the command will
    automatically look up the nonce of the currently active verification,
	and will prompt for the key to be entered:

        $ vault operator verify

    In the sub-form intended for automation, the operation nonce must be
    explicitly provided, and the key is provided directly on the command line

        $ vault operator verify -nonce=... KEY

    If key is specified as "-", the command will read from stdin.

  Form 3 (-status) - Get the status of a verification that is in progress:

        $ vault operator verify -status

  Form 4 (-cancel) - Cancel a verification that is in progress:

        $ vault operator verify -cancel

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *OperatorVerifyQuorumCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP | FlagSetOutputFormat)

	f := set.NewFlagSet("Command Options")

	f.BoolVar(&BoolVar{
		Name:       "init",
		Target:     &c.flagInit,
		Default:    false,
		EnvVar:     "",
		Completion: complete.PredictNothing,
		Usage: "Practice individually providing unseal keys. This can simulate " +
			"unsealing vault, generating new unseal/recovery keys, or generating a new root token.",
	})

	f.BoolVar(&BoolVar{
		Name:       "cancel",
		Target:     &c.flagCancel,
		Default:    false,
		EnvVar:     "",
		Completion: complete.PredictNothing,
		Usage: "Reset the verification. This will discard any " +
			"submitted unseal.",
	})

	f.BoolVar(&BoolVar{
		Name:       "status",
		Target:     &c.flagStatus,
		Default:    false,
		EnvVar:     "",
		Completion: complete.PredictNothing,
		Usage: "Print the status of the current attempt without providing an " +
			"unseal or recovery key.",
	})

	f.StringVar(&StringVar{
		Name:       "nonce",
		Target:     &c.flagNonce,
		Default:    "",
		EnvVar:     "",
		Completion: complete.PredictAnything,
		Usage: "Nonce value returned at initialization. The same nonce value " +
			"must be provided with each unseal or recovery key. Only needed " +
			"when providing an unseal or recovery key.",
	})

	return set
}

func (c *OperatorVerifyQuorumCommand) AutocompleteArgs() complete.Predictor {
	return nil
}

func (c *OperatorVerifyQuorumCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *OperatorVerifyQuorumCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	args = f.Args()
	if len(args) > 1 {
		c.UI.Error(fmt.Sprintf("Too many arguments (expected 0-1, got %d)", len(args)))
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	switch {
	case c.flagCancel:
		return c.cancel(client)
	case c.flagInit:
		return c.init(client)
	case c.flagStatus:
		return c.status(client)
	default:
		// If there are no other flags, prompt for an unseal key.
		key := ""
		if len(args) > 0 {
			key = strings.TrimSpace(args[0])
		}
		return c.provide(client, key)
	}
}

// init is used to start the verification process
func (c *OperatorVerifyQuorumCommand) init(client *api.Client) int {

	// Start the verification
	f := client.Sys().VerifyQuorumInit

	status, err := f()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error initializing verify: %s", err))
		return 2
	}

	switch Format(c.UI) {
	case "table":
		return c.printStatus(status)
	default:
		return OutputData(c.UI, status)
	}
}

// provide prompts the user for the seal key and posts it to the update verification
// endpoint. If this is the last unseal, this function outputs it.
func (c *OperatorVerifyQuorumCommand) provide(client *api.Client, key string) int {
	f := client.Sys().VerifyQuorumStatus

	status, err := f()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error getting verify status: %s", err))
		return 2
	}

	// Verify an attempt is in progress. If there is not one in
	// progress, return an error instructing the user to start one.
	if !status.Started {
		c.UI.Error(wrapAtLength(
			"No verification is in progress. Start a verification by " +
				"running \"vault operator verify -init\"."))
		return 1
	}

	var nonce string

	switch key {
	case "-": // Read from stdin
		nonce = c.flagNonce

		// Pull our fake stdin if needed
		stdin := (io.Reader)(os.Stdin)
		if c.testStdin != nil {
			stdin = c.testStdin
		}

		var buf bytes.Buffer
		if _, err := io.Copy(&buf, stdin); err != nil {
			c.UI.Error(fmt.Sprintf("Failed to read from stdin: %s", err))
			return 1
		}

		key = buf.String()
	case "": // Prompt using the tty
		// Nonce value is not required if we are prompting via the terminal
		nonce = status.Nonce

		w := getWriterFromUI(c.UI)
		fmt.Fprintf(w, "Operation nonce: %s\n", nonce)
		fmt.Fprintf(w, "Unseal Key (will be hidden): ")
		key, err = password.Read(os.Stdin)
		fmt.Fprintf(w, "\n")
		if err != nil {
			if err == password.ErrInterrupted {
				c.UI.Error("user canceled")
				return 1
			}

			c.UI.Error(wrapAtLength(fmt.Sprintf("An error occurred attempting to "+
				"ask for the unseal key. The raw error message is shown below, but "+
				"usually this is because you attempted to pipe a value into the "+
				"command or you are executing outside of a terminal (tty). If you "+
				"want to pipe the value, pass \"-\" as the argument to read from "+
				"stdin. The raw error was: %s", err)))
			return 1
		}
	default: // Supplied directly as an arg
		nonce = c.flagNonce
	}

	// Trim any whitespace from they key, especially since we might have prompted
	// the user for it.
	key = strings.TrimSpace(key)

	// Verify we have a nonce value
	if nonce == "" {
		c.UI.Error("Missing nonce value: specify it via the -nonce flag")
		return 1
	}

	// Provide the key, this may potentially complete the update
	fUpd := client.Sys().VerifyQuorumUpdate

	status, err = fUpd(key, nonce)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error posting unseal key: %s", err))
		return 2
	}
	switch Format(c.UI) {
	case "table":
		return c.printStatus(status)
	default:
		return OutputData(c.UI, status)
	}
}

// cancel cancels the verification
func (c *OperatorVerifyQuorumCommand) cancel(client *api.Client) int {
	f := client.Sys().VerifyQuorumCancel

	if err := f(); err != nil {
		c.UI.Error(fmt.Sprintf("Error canceling verify: %s", err))
		return 2
	}
	c.UI.Output("Success! Verification canceled (if it was started)")
	return 0
}

// status is used just to fetch and dump the status
func (c *OperatorVerifyQuorumCommand) status(client *api.Client) int {
	f := client.Sys().VerifyQuorumStatus

	status, err := f()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error getting verify status: %s", err))
		return 2
	}
	switch Format(c.UI) {
	case "table":
		return c.printStatus(status)
	default:
		return OutputData(c.UI, status)
	}
}

// printStatus dumps the status to output
func (c *OperatorVerifyQuorumCommand) printStatus(status *api.VerifyQuorumStatusResponse) int {
	out := []string{}
	out = append(out, fmt.Sprintf("Nonce | %s", status.Nonce))
	out = append(out, fmt.Sprintf("Started | %t", status.Started))
	out = append(out, fmt.Sprintf("Progress | %d/%d", status.Progress, status.Required))
	out = append(out, fmt.Sprintf("Complete | %t", status.Complete))

	output := columnOutput(out, nil)
	c.UI.Output(output)
	return 0
}
