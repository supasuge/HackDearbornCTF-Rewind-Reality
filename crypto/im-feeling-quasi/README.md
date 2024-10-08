# Im Felling Quasi!
**Author**: [supasuge](https://github.com/supasuge)
**Description**: Let's get quasi baby!
It works as of right now, gonna fix it up for the socat TCP connection to accept user input.

## Dist 
- `dist/chal.py`

***

## Build

```sh
cd crypto/im-feeling-quasi/build
sudo docker build -t im-feeling-quasi .
```

***

## Run

```sh
sudo docker run -p 1337:1337 -d im-feeling-quasi:latest
```