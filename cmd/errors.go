package cmd

import "fmt"

func notImplemented(name string) error {
	return fmt.Errorf("%s: not implemented yet — see https://github.com/Aareez01/kubeinspector/issues", name)
}
