# HackDearbornCTF-2024-Private

Private source repository for the CTF occuring at the hack dearborn event. Categories include Crypto, Web, Forensics, Misc, Reverse Engineering, and Binary Exploitation.

---


## How To Add a Challenge
Please follow the following specifications:
- First make sure you are under the branch with the name `category/challenge-name` (`git checkout -b category/challenge-main`).
- In your branch, create a new directory called `challenge-name` (replacing with the actual name of the challenge) in the corresponding category directory. 
- Create a README.md file in your challenge directory with the challenge description.
    - This README should contain the challenge description, flag format, and any other relevant information.
    - Make sure that it is detailed enough so we can add it with the appropriate description to the CTF platform.



### Directory Structure


```
CTFd-Project/
├── Crypto/
│   ├── Challenge_name/
│   │   ├── build/
│   │   │   ├── Dockerfile
│   │   │   └── requirements.txt
│   │   ├── dist/
│   │   │   └── cipher_challenge.tar.xz
│   │   ├── solution/
│   │   │   ├── solve.py
│   │   │   └── writeup.md
│   │   └── README.md
│   └── Challenge_name/
│       ├── build/
│       │   ├── Dockerfile
│       │   └── requirements.txt
│       ├── dist/
│       │   └── challenge.tar.xz
│       ├── solution/
│       │   ├── solve.py
│       │   └── writeup.md
│       └── README.md
├── Web/
│   ├── Challenge_name/
│   │   ├── build/
│   │   │   ├── Dockerfile
│   │   │   └── requirements.txt
│   │   ├── dist/
│   │   │   └── challenge.tar.xz
│   │   ├── solution/
│   │   │   ├── solve.py
│   │   │   └── writeup.md
│   │   └── README.md
│   └── Challenge_name/
│   │   ├── build/
│   │   │   ├── Dockerfile
│   │   │   └── requirements.txt
│   │   ├── dist/
│   │   │   └── challenge.tar.xz
│   │   ├── solution/
│   │   │   ├── solve.py
│   │   │   └── writeup.md
│   │
│   └── Challenge_name/
│       ├── build/
│       │   ├── Dockerfile             <-- Dockerfile for deploying challenge
│       │   └── requirements.txt       <-- requirements
│       ├── dist/
│       │   └── challenge.tar.xz       <-- Challenge archive of file to be distributed to user. 
│       ├── solution/
│       │   ├── solve.py               <-- Solutions script
│       │   └── writeup.md             <-- Writeup/explaination
│       └── README.md
├── Rev/
│   ├── ChallengeName/
│   │   ├── build/
│   │   │   ├── Dockerfile
│   │   │   └── requirements.txt
│   │   ├── dist/
│   │   │   └── rev_challenge.exe
│   │   ├── solution/
│   │   │   ├── solve_rev.py
│   │   │   └── writeup.md
│   │   └── README.md
│   └── ChallengeName/
│       ├── build/
│       │   ├── Dockerfile
│       │   └── requirements.txt
│       ├── dist/
│       │   └── challenge.bin
│       │   └── source_code.c - optional
│       ├── solution/
│       │   ├── solve_analysis.py
│       │   └── writeup.md
│       └── README.md
├── Misc/
│   ├── ChallengeName/
│   │   ├── build/
│   │   │   ├── Dockerfile
│   │   │   └── requirements.txt
│   │   ├── dist/
│   │   │   └── hidden.tar.xz
│   │   ├── solution/
│   │   │   ├── solve.py
│   │   │   └── writeup.md
│   │   └── README.md
│   └── ChallengeName/
│       ├── build/
│       │   ├── Dockerfile
│       │   └── requirements.txt
│       ├── dist/
│       │   └── challenge.txt
│       ├── solution/
│       │   ├── solve.py
│       │   └── writeup.md
│       └── README.md
├── Forensics/
│   ├── memory-dump/
│   │   ├── build/
│   │   │   ├── Dockerfile
│   │   │   └── requirements.txt
│   │   ├── dist/
│   │   │   └── memory_dump.raw
│   │   ├── solution/
│   │   │   ├── solve_memory.py
│   │   │   └── writeup.md
│   │   └── README.md
│   └── network-sniffing/
│       ├── build/
│       │   ├── Dockerfile
│       │   └── requirements.txt
│       ├── dist/
│       │   └── network_capture.pcap
│       ├── solution/
│       │   ├── solve_network.py
│       │   └── writeup.md
│        └── README.md
│  
├── Binary-Exploitation-Pwn/
│   ├── buffer-overflow/
│   │   ├── build/
│   │   │   ├── Dockerfile
│   │   │   └── requirements.txt
│   │   ├── dist/
│   │   │   └── overflow_challenge
│   │   ├── solution/
│   │   │   ├── solve_overflow.py
│   │   │   └── writeup.md
│   │   └── README.md
│   └── format-string/
│       ├── build/
│       │   ├── Dockerfile
│       │   └── requirements.txt
│       ├── dist/
│       │   └── format_string_challenge
│       ├── solution/
│       │   ├── solve_format.py
│       │   └── writeup.md
│       └── README.md
├── scripts/
│   └── deploy.sh <-- Deployment of any system services/required installation plugins 
├── docs/
│   └── CONTRIBUTING.md
└── README.md

    


```