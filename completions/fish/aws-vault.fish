complete -c aws-vault -x -a '(__fish_aws_vault_completion)'

function __fish_aws_vault_completion
  if [ (count (commandline -opc)) = 1 ]
    __fish_print_aws_vault_commands
  else
    __fish_print_aws_roles
  end
end

function __fish_print_aws_vault_commands
  aws-vault --help |awk '/^  [a-z]/ {print $1}'
end

function __fish_print_aws_roles
  awk '/^\[profile/ {print $2}' ~/.aws/config |tr -d ']'
end
