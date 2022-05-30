# smoke-test

Contains a small subset of functionality tests for ospd-openvas within a controlled environment.

To build and run the tests a Makefile is provided:
- make build - builds the image `greenbone/ospd-openvas-smoketests`
- make run - runs the image `greenbone/ospd-openvas-smoketests`
- make - builds and run the image `greenbone/ospd-openvas-smoketests`

To verify your local environment you need to have `go` installed:

```
OSPD_SOCKET=$PATH_TO_YOUR_OSPD_SOCKET go run cmd/test/main.go
```

Be aware that you need to have the nasl files within `./data/plugins` within your feed dir and the notus advisories `./data/notus/advisories` installed in your notus advisory dir.
