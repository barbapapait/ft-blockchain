package main

import (
	"os"
	"sort"

	_ "ft-blockchain/cli"
	"ft-blockchain/cli/asset"
	"ft-blockchain/cli/bookkeeper"
	. "ft-blockchain/cli/common"
	"ft-blockchain/cli/consensus"
	"ft-blockchain/cli/data"
	"ft-blockchain/cli/debug"
	"ft-blockchain/cli/info"
	"ft-blockchain/cli/multisig"
	"ft-blockchain/cli/privpayload"
	"ft-blockchain/cli/recover"
	"ft-blockchain/cli/smartcontract"
	"ft-blockchain/cli/test"
	"ft-blockchain/cli/wallet"

	"github.com/urfave/cli"
)

var Version string

func main() {
	app := cli.NewApp()
	app.Name = "nodectl"
	app.Version = Version
	app.HelpName = "nodectl"
	app.Usage = "command line tool blockchain node"
	app.UsageText = "nodectl [global options] command [command options] [args]"
	app.HideHelp = false
	app.HideVersion = false
	//global options
	app.Flags = []cli.Flag{
		NewIpFlag(),
		NewPortFlag(),
	}
	//commands
	app.Commands = []cli.Command{
		*consensus.NewCommand(),
		*debug.NewCommand(),
		*info.NewCommand(),
		*test.NewCommand(),
		*wallet.NewCommand(),
		*asset.NewCommand(),
		*privpayload.NewCommand(),
		*data.NewCommand(),
		*bookkeeper.NewCommand(),
		*recover.NewCommand(),
		*multisig.NewCommand(),
		*smartcontract.NewCommand(),
	}
	sort.Sort(cli.CommandsByName(app.Commands))
	sort.Sort(cli.FlagsByName(app.Flags))

	app.Run(os.Args)
}
