package main

import (
	"fmt"

	"homeproxy-cli/internal/system"
)

func controlCommand(args []string) error {
	if err := system.CheckInstalled(); err != nil {
		return err
	}

	if err := requireRoot(); err != nil {
		return err
	}

	if len(args) == 0 {
		return fmt.Errorf("usage: homeproxy control <start|stop|restart|status>")
	}

	action := args[0]

	switch action {
	case "start":
		if err := system.ServiceStart(); err != nil {
			return err
		}
		logInfo("HomeProxy started")
	case "stop":
		if err := system.ServiceStop(); err != nil {
			return err
		}
		logInfo("HomeProxy stopped")
	case "restart":
		if err := system.ServiceRestart(); err != nil {
			return err
		}
		logInfo("HomeProxy restarted")
	case "status":
		_, out, err := system.ServiceStatus()
		if err != nil {
			// Still print whatever status output we have.
			logWarn(err.Error())
		}
		if out != "" {
			fmt.Println(out)
		}
	default:
		return fmt.Errorf("usage: homeproxy control <start|stop|restart|status>")
	}

	return nil
}

