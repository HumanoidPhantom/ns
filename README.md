# ns
Naming Server

Build: docker build -t ns .

[PORT] should be specified:
Run: docker run --rm -p [PORT]:9090 -v $(pwd)/files:/ns/files:rw -it --name ns ns

[](https://github.com/Zilborg/client_fuse)

Client:
Storage Server: [](https://github.com/Kazakov-A/Distributed-storage)