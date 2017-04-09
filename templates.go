package main

// copied from https://github.com/alecthomas/kingpin/blob/bf41f6e3a31bed72c020e920c5fcf6349040c565/templates.go

var bashCompletionTemplate = `
{{.App.Name}}_bash_autocomplete() {
    local cur prev words cword
    local i

    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    for (( i=1; i <= COMP_CWORD; i++ )); do
        if [[ ${COMP_WORDS[i]} == -- ]]; then
            local root_command=${COMP_WORDS[i]}
            _command_offset $i+1
            return
        fi
    done
}
complete -F _{{.App.Name}}_bash_autocomplete {{.App.Name}}
`

var zshCompletionTemplate = `
#compdef {{.App.Name}}
autoload -U compinit && compinit
autoload -U bashcompinit && bashcompinit
_{{.App.Name}}_bash_autocomplete() {
    local cur prev opts base
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    opts=$( ${COMP_WORDS[0]} --completion-bash ${COMP_WORDS[@]:1:$COMP_CWORD} )
    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
    return 0
}
complete -F _{{.App.Name}}_bash_autocomplete {{.App.Name}}
`
