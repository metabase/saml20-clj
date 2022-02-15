#! /usr/bin/env bash

set -euxo pipefail

script_directory=`dirname "${BASH_SOURCE[0]}"`
cd "$script_directory/.."

version=$(cat VERSION.txt)

clojure -X:jar :version "\"$version\""

clojure -X:deploy :artifact target/whitespace-linter.jar
