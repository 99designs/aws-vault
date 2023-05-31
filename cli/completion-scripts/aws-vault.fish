if status --is-interactive
  complete -ec aws-vault

  # switch based on seeing a `--`
  complete -c aws-vault -n 'not __fish_aws_vault_is_commandline' -xa '(__fish_aws_vault_complete_arg)'
  complete -c aws-vault -n '__fish_aws_vault_is_commandline' -xa '(__fish_aws_vault_complete_commandline)'

  function __fish_aws_vault_is_commandline
    string match -q -r '^--$' -- (commandline -opc)
  end

  function __fish_aws_vault_complete_arg
    set -l parts (commandline -opc)
    set -e parts[1]

    aws-vault --completion-bash $parts
  end

  function __fish_aws_vault_complete_commandline
    set -l parts (string split --max 1 '--' -- (commandline -pc))

    complete "-C$parts[2]"
  end
end
