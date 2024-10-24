# HackDearbornCTF-2024-Private

**Flag Format**: `hd3{}`

Source repository for the small CTF at [Hack Dearborn: Rewind Reality](https://www.hackdearborn.org/) as part of the Cybersecurity challenges!

**Unsolved challenge solutions + explaination**:
- [Combined multiple recursive... what? (Crypto, Hard) - Writeup](https://github.com/supasuge/HackDearbornCTF-Rewind-Reality/blob/main/crypto/combined-multiple-recursive...what/solution/WRITEUP.md)
- [Cop or smith? (Crypto, Hard) - Writeup](https://github.com/supasuge/HackDearbornCTF-Rewind-Reality/blob/main/crypto/cop-or-smith/solution/README.md)
  - Please let me know if I made any error's in the LaTex math equations and/or the formatting of the LaTex in the above two writeup's if at all possible, I am still learning LaTex syntax so it's possible there are small error's format wise. I spent lot's of time on the above two write-ups so I hope they are beneficial to someone :)
- **I'm feeling quasi (Crypto, Medium)**: Challenge loosely based off of the *(Fully broken)* Xifrat compact Public Key Cryptosystem based on Quasigroups. **Coming soon**
- **Time will tell (Web, Hard)**: Timing attack on vulnerable `strcmp` function that implement's a 0.19ms sleep for easier statistical measurements and to account for the load/amount of requests being handled by WSGI Asynch server. **Coming soon**
- **Beep beep boop beep (Misc, Hard)**: Fun OSINT/Misc challenge in which I converted a QR Code image containing the encoded flag into it's binary representation then converted said binary string to a morse code audio file (0=800Hz, 1=1200Hz). Intended solution is to use `pydub` or a spectrum analyzer to automate the processing of the audio file to recover the `.png` QR Code from the raw binary itself represented by the morse code audio.

***

Authors:

- [supasuge - Evan Pardon](https://github.com/supasuge)
- [shams-ahson - Shams Ahson](https://github.com/shams-ahson)

---

## 📂 Directory Structure

🔍 Directory Details
- Category Directories
  - `crypto/`
  - `web/`
  - `rev/`
  - `misc/`
  - `forensics/`
  - `pwn/`: Didn't end up having time to finish these. None in prod.
- 3-5 challenges per category.
  - Subdirectories for each challenge:
  - `build/`: 
    - Contains the files necessaries to build/deploy the chalenge
  - `dist/`:
    - Stores the file/s or archive to distribute to challenge participant.
  - `solution/`:
    - Includes solution scripts (`solve.py`, etc.) and writeups 
  - `README.md`:
    - Provides brief description of challenge points, flag format, and build/dist information.

---
