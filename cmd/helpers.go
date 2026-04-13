package cmd

func resolveNS(opts *GlobalOptions, defaultNS string) string {
	if opts.AllNS {
		return ""
	}
	if opts.Namespace != "" {
		return opts.Namespace
	}
	return defaultNS
}
