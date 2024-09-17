#!/bin/bash

configs=(
	"windows amd64"
	"windows arm64"
	"linux amd64"
	"linux arm64"
	"darwin arm64"
)

mkdir -p bin
for config in "${configs[@]}"; do
	read -r goos goarch <<<"$config"
	echo $goos $goarch
	output=bin/azure-keyvault-pgp-${goos}-${goarch}
	if [ "$goos" == "windows" ]; then
		output+=".exe"
	fi
	GOOS=$goos GOARCH=$goarch CGO_ENABLED=0 go build -o "$output"
done
