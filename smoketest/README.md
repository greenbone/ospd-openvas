# smoke-test

Contains a small subset of functionality tests for ospd-openvas within a controlled environment.

To build and run the tests a Makefile is provided:
- make build-cmds - creates the go binaries within bin/
- make fetch-nasl - fetches the newest community feed into `.nasl/`
- make fetch-scan-configs - fetches the newest scan-configs/policies into `.scan-configs/`
- make build - builds the image `greenbone/ospd-openvas-smoketests`
- make run - runs the image `greenbone/ospd-openvas-smoketests`
- make - builds and run the image `greenbone/ospd-openvas-smoketests`

Unfortunately the community images are not deployed into docker hub yet. 

You have to login within ghcr.io:

```
echo <your_github_token> | docker login ghcr.io -u <your_github_handle> --password-stdin
```

To verify your local environment you need to have `go` installed:

```
OSPD_SOCKET=$PATH_TO_YOUR_OSPD_SOCKET go run cmd/test/main.go
```

Be aware that you need to have the nasl files within `./data/plugins` within your feed dir and the notus advisories `./data/notus/advisories` installed in your notus advisory dir.

To run the policy tests you also need to have the dependent scripts installed. To prepare that you can run:

```
go run cmd/feed-preparer/main.go -p .scan-configs -s .nasl -t /var/lib/openvas/plugins
```

This will parse the given scan configs and copy the necessary plugins from <path_to_existing_feed> to <path_to_new_target>.

On top of that you need to have a local ssh-server running and populate user credentials via `USERNAME` and `PASSWORD`; otherwise the policy test will fail because they're unable to connect to ssh.

