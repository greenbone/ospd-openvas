# smoke-test

Contains a small subset of functionality tests for ospd-openvas within a controlled environment.

To build and run the tests execute:

```
DOCKER_BUILDKIT=1 docker build -t greenbone/ospd-openvas smoketest/
docker run --rm greenbone/ospd-openvas
```

