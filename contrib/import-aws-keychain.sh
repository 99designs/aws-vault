#!/bin/bash

for key in $(aws-keychain ls) ; do
  echo importing $key
  aws-keychain exec "$key" aws-vault add "$key" --env
done