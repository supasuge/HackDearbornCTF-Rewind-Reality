# HackDearbornCTF-2024-Private

Private source repository for the CTF occuring at the hack dearborn event. Categories include Crypto, Web, Forensics, Misc, Reverse Engineering, and Binary Exploitation.

---

## 📂 Purpose of the Repository

This repository serves as the centralized location for developing, organizing, and managing challenges for the HackDearborn CTF-2024 event. It ensures a structured approach to challenge creation, collaboration between team members, and seamless integration with the CTFd platform.
What to Include:

- **Challenges**: Organized by category with all necessary files for deployment and solutions.
- **Scripts**: Utility scripts for deployment and automation.
- **Documentation**: Guidelines for contributing, challenge creation, and project setup.
- **Solutions**: Solution scripts and/or writeups must be provided to validate the challenge is working and solveable.

---

## 📁 Directory Structure

🔍 Directory Details
- Category Directories (`crypto/`, `web/`, `rev/`, `misc/`, `forensics/`, `pwn/`):
  - Each category contains multiple challenges.
  - Challenge Directory (`challenge-name/`):
  - `build/`: 
    - Contains the `Dockerfile` and `requirements.txt` (if applicable) for building the challenge environment + any other source code needed + dependencies.
  - `dist/`:
    - Stores challenge-specific files to be distributed to participants (e.g., archives, executables).
  - `solution/`:
    - Includes solution scripts (`solve.py`, etc.) and detailed writeups (`writeup.md`).
  - `README.md`:
    - Provides a comprehensive description of the challenge, including objectives, flag format, and any additional instructions or hints.
  - `scripts/`:
    - Contains utility scripts such as deployment scripts (deploy.sh) for setting up services or installing necessary plugins.
  - `docs/`:
    - Holds documentation files like CONTRIBUTING.md which outlines guidelines for contributing to the repository.

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

- (*TBD*) Create a chal.<category>.<name>.yml file in the .github/workflows/ directory to build the challenge. Ignore this step for now.

> [!WARNING]
> Ignore the workflows for now

Once made, please push your branch to the repository and create a pull request to merge it into the main branch.

---

#### Checklist:

Each time a challenge is added, please be sure to come here and update the README.md in your current branch.

- [ ] **Crypto**:
    - [ ] *Challenge Name 1*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
    
    - [ ] *Challenge Name 2*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:    
        - *Dist files*: (These are the file to be distributed to the player if any)
    
    - [ ] *Challenge Name 3*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
    
    - [ ] *Challenge Name 4*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
    
    - [ ] *Challenge Name 5*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
 
    - [ ] *Challenge Name 6*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
         

- [ ] **Miscellaneous**:
    - [ ] *Challenge Name 1*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
    
    - [ ] *Challenge Name 2*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
    
    - [ ] *Challenge Name 3*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
    
    - [ ] *Challenge Name 4*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
    
    - [ ] *Challenge Name 5*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any) 


- [ ] **Rev**:
    - [ ] *Challenge Name 1*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
    
    - [ ] *Challenge Name 2*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
    
    - [ ] *Challenge Name 3*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
    
    - [ ] *Challenge Name 4*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)

         
- [ ] **Forensics**:
    - [ ] *Challenge Name 1*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
    
    - [ ] *Challenge Name 2*- [ ] *Challenge Name 4*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
    
    - [ ] *Challenge Name 3*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
    
    - [ ] *Challenge Name 4*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
    
    - [ ] *Challenge Name 5*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
    
    - [ ] *Challenge Name 6*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)


- [ ] **Web Exploitation**:
    - [ ] *Challenge Name 1*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
    
    - [ ] *Challenge Name 2*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
    
    - [ ] *Challenge Name 3*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
    
    - [ ] *Challenge Name 4*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
    
    - [ ] *Challenge Name 5*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)****


- [ ] **Binary Exploitation** 
    - [ ] *Challenge Name 1*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
    
    - [ ] *Challenge Name 2*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
    
    - [ ] *Challenge Name 3*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
    
    - [ ] *Challenge Name 4*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)
    
    - [ ] *Challenge Name 5*
        - *Difficulty: (Easy/Med/Hard)*
        - *Description *1-2 sentences max*:
        - *Dist files*: (These are the file to be distributed to the player if any)

     
**Total: 31 Challenges planned above**

---

### How To Add a Challenge to repository (Example workflow included)


To create challenges please follow the following specifications:

First off, clone the respository locally then `cd` into it:

```bash
git clone https://github.com/supasuge/HackDearbornCTF-2024-Private.git
cd HackDearbornCTF-2024-Private
```

- Create a branch for the challenge you are creating `category/challenge-name` (`git checkout -b category/challenge-name`). It's important to note here that github branches cannot contain uppercases or special character other than `-`.

- In your branch, under the correct category create a new directory called `challenge-name` (replacing with the actual name of the Challenge Name) in the corresponding category directory. 

- Create a `README.md` file in your Challenge Name directory with the Challenge Name description.
    - This `README.md` should contain the **Challenge Name**, **description**, **flag format**, and **any other relevant information towards build/deployment and usage**.
    - Make sure that it is detailed enough so we can add it with the appropriate description to the CTF platform.


#### Example Workflow for a new challenge

```bash
#!/bin/bash
# Make sure you `cd` into HackDearbornCTF-2024-Private first

# Create a new branch and use it, then add challenge content
git checkout -b crypto/oh-sike-wrong-number                                        # Create a new branch for Challenge Name oh-sike-wrong-number. Github doesn't allow uppercase letters as branch names.
mkdir -p crypto/oh-sike-wrong-number/build                                         # Files required to build the Challenge Name in a .tar.xz formatted archive 
mkdir -p crypto/oh-sike-wrong-number/dist                                          # Any files to be distributed to player 
mkdir -p crypto/oh-sike-wrong-number/solution                                      # Challenge Name solution files + README.md explaination.
touch crypto/oh-sike-wrong-number/solution/README.md                               # Create README.md: Detailed Challenge Name writeup.
touch crypto/oh-sike-wrong-number/solution/solve.py                                # Solution script
touch crypto/oh-sike-wrong-number/build/Dockerfile                                 # Note that if not live running service is needed, you don't need a docker file.

# Change to directory with build files
cd Crypto/oh-sike-wrong-number/build/                                              # After creating and testing build files, use tar to convert -> .tar.xz archive for storage.
tar -cJf archive-name.tar.xz *                                                     # Will take all the files from the current directory and archive them.
rm -f <chal.py> <output.txt>                                                       # Perform cleanup, remove files leftover that have been archived... File names will differ here.
cd ../../../                                                                                 
git add .                                                                          # Add all changes made to prepare to be pushed to the repo
git commit -m "Message describing changes/challenge/additions"
git push origin crypto/oh-sike-wrong-number
```

### Workflow broken down

1. clone repo and cd into it....
2. `pwd` == `HackDearbornCTF-2024-Private`
3. Create a new branch for the challenge

```bash
git checkout -b crypto/<chal_name>
```

4. Create challenge directories and subdirectories with correct files according to specification

```bash
mkdir -p crypto/<chal_name>            # Challenge root directory under it's corresponding category
mkdir -p crypto/<chal_name>/dist       # Files for user
mkdir -p crypto/<chal_name>/build      # Files required for building the challenge
mkdir -p crypto/<chal_name>/solution   # Files for solving/testing challenge
```

5. Add `README.md` file with Challenge Information
```bash
cat <<EOL > crypto/<chal_name>/README.md
# {Name of challenge}
- Author: {[name on github](https://www.youtube.com/watch?v=GFq6wH5JR2A)}
- Difficulty: {Easy, Medium, Hard, Expert}

## Description
{Short 1 paragraphy summary/description of challenge.}

## Dist
{chal.py} {output.txt} # File to be distributed to playrtd

## Build Instructions
{Include instructions on building/running the challenge here}
Ex:
\`\`\`bash
cd crypto/<chal_name>/build/
docker build -t crypto_name .
\`\`\`

## Run Instructiuon
How to run your challenge/deploy it.
\`\`\`bash
docker run -p 1227:1227 crypto_name -d
EOL
\`\`\`
```

6. Ensure there is a working `Dockerfile` under the `build/` directory if a running service is needed for your challenge, for static challenges you don't need a `Dockerfile`
    a. Make sure there is sufficient dependencies such as modules stored sequentially in `requirements.txt` required for building the challenge.

7. Add Distribution files to `dist/`:
    a. These will be the files or assets handed out to the user. For more than one file or especially directories
    b. Use `tar -cJf archive-name.tar.xz /path/to/directory_or_files`, `tar -xJf <archive.tar.xz>` for extraction.

> [!NOTE]
> Make sure to capitalize the first letter of the challenge category when creating a new branch to maintain symmetry (this will drive me nuts pls_.

---

### Example Directory Structure

Below is an example of what two challenge's from the `crypto` category should look like.

```bash
|HackDearbornCTF-2024-Private/
│ crypto/
│   ├── blocks-on-blocks-on-rocks/
│   │   ├── README.md
│   │   ├── build/
│   │   │   ├── Dockerfile
│   │   │   └── app.py
│   │   ├── dist/
│   │   │   └── app.py
│   │   └── solution/
│   │       ├── WRITEUP.md
│   │       └── solve.py
│   └── oh-sike-wrong-number
│       ├── README.md
│       ├── build/
│       │   ├── Dockerfile
│       │   └── chal.py
│       ├── dist/
│       │   ├── chal.py
│       │   └── out.txt
│       └── solution/
│           ├── WRITEUP.md
│           └── solve.py
```

---

#### Challenge README.md Information

Make sure each challenge README.md includes the following:

```md
# Challenge Name
- **Author**: {Author}
- **Description**: {Description}
- **Difficulty**: {EASY|MEDIUM|HARD|EXPERT}

## Description
Description of the challenge.

## Dist files
File to be distributed

## Build
Information related to building the challenge.

## Run
Information related to running the challenge.

```

___