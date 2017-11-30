# ns
Naming Server

Build: docker build -t ns .

[PORT] should be specified:
Run: docker run --rm -p [PORT]:9090 -v $(pwd)/files:/ns/files:rw -it --name ns ns

Client: [Zilborg/client_fuse](https://github.com/Zilborg/client_fuse)

Storage Server: [Kazakov-A/Distributed-storage](https://github.com/Kazakov-A/Distributed-storage)