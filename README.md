# HackDearbornCTF-2024-Private

Private source repository for the CTF occuring at the hack dearborn event. Categories include Crypto, Web, Forensics, Misc, Reverse Engineering, and Binary Exploitation.

---

📂 Purpose of the Repository

This repository serves as the centralized location for developing, organizing, and managing challenges for the HackDearborn CTF-2024 event. It ensures a structured approach to challenge creation, collaboration between team members, and seamless integration with the CTFd platform.
What to Include:

    Challenges: Organized by category with all necessary files for deployment and solutions.
    Scripts: Utility scripts for deployment and automation.
    Documentation: Guidelines for contributing, challenge creation, and project setup.

📁 Directory Structure

Below is the standardized and generic directory structure for the CTFd project. Follow these conventions to maintain consistency and ease of navigation.


---

## How To Add a Challenge
Please follow the following specifications:
- First make sure you are under the branch with the name `category/challenge-name` (`git checkout -b category/challenge-main`).
- In your branch, create a new directory called `challenge-name` (replacing with the actual name of the challenge) in the corresponding category directory. 
- Create a README.md file in your challenge directory with the challenge description.
  - This README should contain the challenge description, flag format, and any other relevant information.
  - Make sure that it is detailed enough so we can add it with the appropriate description to the CTF platform.

- In challenge directory, create a `buiild` directory with a `Dockerfile` and any other necessary files to build the challenge.
  - Make sure that this directory contains all necessary files to build the challenge and isn't missing and dependencies in the `Dockerfile`.
- If your challenge requires a handout, please put all attachment related files in the dist directory

- If you have any solve scripts, writeups, or other solution-related files, please put them in the solution directory.

- (TBD) Create a chal.<category>.<name>.yml file in the .github/workflows/ directory to build the challenge. Ignore this step for now.


Once made, please push your branch to the repository and create a pull request to merge it into the main branch.

Please follow the below specified file structure to add a challenge.



### Directory Structure

```
|HackDearbornCTF-2024-Private/
├── crypto/
│   ├── challenge-name/
│   │   ├── build/
│   │   │   ├── Dockerfile                  # Dockerfile for deploying the challenge
│   │   │   └── requirements.txt            # Python dependencies (if any)
│   │   ├── dist/
│   │   │   └── challenge-archive.tar.xz     # Challenge files to be distributed to users
│   │   ├── solution/
│   │   │   ├── solve.py                     # Solution script
│   │   │   └── writeup.md                   # Detailed writeup/explanation
│   │   └── README.md                        # Challenge description and specifications
│   └── another-challenge/
│       ├── build/
│       │   ├── Dockerfile
│       │   └── requirements.txt
│       ├── dist/
│       │   └── another-challenge.tar.xz
│       ├── solution/
│       │   ├── solve.py
│       │   └── writeup.md
│       └── README.md
├── web/
│   ├── challenge-name/
│   │   ├── build/
│   │   │   ├── Dockerfile
│   │   │   └── requirements.txt
│   │   ├── dist/
│   │   │   └── challenge-archive.tar.xz
│   │   ├── solution/
│   │   │   ├── solve.py
│   │   │   └── writeup.md
│   │   └── README.md
│   └── another-challenge/
│       ├── build/
│       │   ├── Dockerfile                    # Dockerfile for deploying challenge
│       │   └── requirements.txt              # Python dependencies (if any)
│       ├── dist/
│       │   └── challenge-archive.tar.xz       # Challenge archive to be distributed to users
│       ├── solution/
│       │   ├── solve.py                       # Solution script
│       │   └── writeup.md                     # Writeup/explanation
│       └── README.md
├── reverse-engineering/
│   ├── challenge-name/
│   │   ├── build/
│   │   │   ├── Dockerfile
│   │   │   └── requirements.txt
│   │   ├── dist/
│   │   │   └── challenge-file.exe             # Executable or relevant challenge file
│   │   ├── solution/
│   │   │   ├── solve_reverse.py               # Solution script
│   │   │   └── writeup.md                     # Writeup/explanation
│   │   └── README.md
│   └── another-challenge/
│       ├── build/
│       │   ├── Dockerfile
│       │   └── requirements.txt
│       ├── dist/
│       │   └── challenge-file.bin
│       │   └── source_code.c                 # Optional source code
│       ├── solution/
│       │   ├── solve_analysis.py             # Solution script
│       │   └── writeup.md                     # Writeup/explanation
│       └── README.md
├── misc/
│   ├── challenge-name/
│   │   ├── build/
│   │   │   ├── Dockerfile
│   │   │   └── requirements.txt
│   │   ├── dist/
│   │   │   └── hidden-files.tar.xz          # Files related to the challenge
│   │   ├── solution/
│   │   │   ├── solve.py                     # Solution script
│   │   │   └── writeup.md                   # Writeup/explanation
│   │   └── README.md
│   └── another-challenge/
│       ├── build/
│       │   ├── Dockerfile
│       │   └── requirements.txt
│       ├── dist/
│       │   └── challenge-description.txt     # Text or other relevant files
│       ├── solution/
│       │   ├── solve.py                       # Solution script
│       │   └── writeup.md                     # Writeup/explanation
│       └── README.md
├── forensics/
│   ├── memory-dump/
│   │   ├── build/
│   │   │   ├── Dockerfile
│   │   │   └── requirements.txt
│   │   ├── dist/
│   │   │   └── memory_dump.raw               # Forensic image
│   │   ├── solution/
│   │   │   ├── solve_memory.py               # Solution script
│   │   │   └── writeup.md                     # Writeup/explanation
│   │   └── README.md
│   └── network-sniffing/
│       ├── build/
│       │   ├── Dockerfile
│       │   └── requirements.txt
│       ├── dist/
│       │   └── network_capture.pcap           # Network capture file
│       ├── solution/
│       │   ├── solve_network.py               # Solution script
│       │   └── writeup.md                     # Writeup/explanation
│        └── README.md
│  
├── binary-exploitation-pwn/
│   ├── buffer-overflow/
│   │   ├── build/
│   │   │   ├── Dockerfile
│   │   │   └── requirements.txt
│   │   ├── dist/
│   │   │   └── overflow_challenge             # Executable or relevant file
│   │   ├── solution/
│   │   │   ├── solve_overflow.py             # Solution script
│   │   │   └── writeup.md                     # Writeup/explanation
│   │   └── README.md
│   └── format-string/
│       ├── build/
│       │   ├── Dockerfile
│       │   └── requirements.txt
│       ├── dist/
│       │   └── format_string_challenge         # Executable or relevant file
│       ├── solution/
│       │   ├── solve_format.py                 # Solution script
│       │   └── writeup.md                     # Writeup/explanation
│       └── README.md
├── scripts/
│   └── deploy.sh                                # Deployment of system services or required installation plugins 
├── docs/
│   └── CONTRIBUTING.md                           # Contribution guidelines
└── README.md

```

🔍 Directory Details

    Category Directories (crypto/, web/, reverse-engineering/, misc/, forensics/, binary-exploitation-pwn/):
        Each category contains multiple challenges.
        Challenge Directory (challenge-name/):
            build/: Contains the Dockerfile and requirements.txt (if applicable) for building the challenge environment.
            dist/: Stores challenge-specific files to be distributed to participants (e.g., archives, executables).
            solution/: Includes solution scripts (solve.py, etc.) and detailed writeups (writeup.md).
            README.md: Provides a comprehensive description of the challenge, including objectives, flag format, and any additional instructions or hints.

    scripts/:
        Contains utility scripts such as deployment scripts (deploy.sh) for setting up services or installing necessary plugins.

    docs/:
        Holds documentation files like CONTRIBUTING.md which outlines guidelines for contributing to the repository.