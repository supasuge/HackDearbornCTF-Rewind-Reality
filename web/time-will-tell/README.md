# CHANGE_ME_6

## Description

Basic flask API with an index page with documentation for usage of the different endpoints and there parameters. Goal of this challenge is to perform a timing attack on the decorator on the `/adminpanel` using the vulnerability present in `strcmp` in which a timing vulnerability is introduced due to the way python compares string values. A slight 6-9ms sleep was added to help this challenge be more easily solvable to account for a high volume of network traffic and the use of automated scripts sending large amounts of requests. Healthcheck's are performed via a crontab script not included in the repo to make sure there wasn't any issues timing wise and it was still solvable quite frequently. Never failed once, LFG.

## Dist
- `chal.tar.xz`

## Build

```sh
cd time-will-tell/build
docker build -t time-will-tellv0.1 .
```

## Run

```sh
docker run -d -p 8000:8000 time-will-tellv0.1
```

### Solution
[solution/solve.py](./solution/solve.py)
