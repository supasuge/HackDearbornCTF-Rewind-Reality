# Lost Park

OSINT challenge

## Dist
- `dist/image.png`


## Build
Have tried rust server, rust binary that runs over `socat` to forward stdin/out over TCP, and both in python. CTFd just wont gimme a mf port smh


## Run

```sh
cd build/
docker build -t lost-park .
docker run -d -p 9494:9494 --rm lost-park
```
