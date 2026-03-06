package main

import "fmt"

const completionBash = `_homeproxy() {
    local cur prev
    
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    commands="node routing dns subscription status log control features resources acl cert generator help"
    
    case "${COMP_CWORD}" in
        1)
            COMPREPLY=($(compgen -W "${commands}" -- ${cur}))
            ;;
        2)
            case "${prev}" in
                node)
                    COMPREPLY=($(compgen -W "list test set-main add remove edit import export" -- ${cur}))
                    ;;
                routing)
                    COMPREPLY=($(compgen -W "get set set-node rules status" -- ${cur}))
                    ;;
                dns)
                    COMPREPLY=($(compgen -W "get set set-china status test cache strategy" -- ${cur}))
                    ;;
                subscription)
                    COMPREPLY=($(compgen -W "list add remove update auto-update filter status" -- ${cur}))
                    ;;
                log)
                    COMPREPLY=($(compgen -W "clean homeproxy sing-box-c sing-box-s" -- ${cur}))
                    ;;
                control)
                    COMPREPLY=($(compgen -W "start stop restart status" -- ${cur}))
                    ;;
                resources)
                    COMPREPLY=($(compgen -W "version update" -- ${cur}))
                    ;;
                acl)
                    COMPREPLY=($(compgen -W "list write" -- ${cur}))
                    ;;
                cert)
                    COMPREPLY=($(compgen -W "write" -- ${cur}))
                    ;;
                generator)
                    COMPREPLY=($(compgen -W "uuid reality-keypair wg-keypair vapid-keypair ech-keypair" -- ${cur}))
                    ;;
            esac
            ;;
    esac
    
    return 0
}

complete -F _homeproxy homeproxy
`

func completionCommand(args []string) error {
	if len(args) == 0 || args[0] != "bash" {
		return fmt.Errorf("usage: homeproxy completion bash")
	}
	fmt.Print(completionBash)
	return nil
}
