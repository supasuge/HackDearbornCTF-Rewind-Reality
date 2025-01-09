# HackDearbornCTF-2024 Source

**Flag Format**: `hd3{}`

Source code + writeup repository for the small CTF at [Hack Dearborn: Rewind Reality](https://www.hackdearborn.org/) as part of the Cybersecurity challenges! 

> This *CTF* was rushed quite a bit thus the incompleteness. Overall, still some pretty cool and fun challenges!

**Unsolved challenge solutions + explaination**:
- [Combined multiple recursive... what? (Crypto, Hard) - Writeup](https://github.com/supasuge/HackDearbornCTF-Rewind-Reality/blob/main/crypto/combined-multiple-recursive...what/solution/WRITEUP.md)
- [Cop or smith? (Crypto, Hard) - Writeup](https://github.com/supasuge/HackDearbornCTF-Rewind-Reality/blob/main/crypto/cop-or-smith/solution/README.md)
- **I'm feeling quasi (Crypto, Medium)**: Challenge loosely based off of the *(Fully broken)* Xifrat compact Public Key Cryptosystem based on Quasigroups.
- **Time will tell (Web, Hard)**: Asynchronous timing attack on vulnerable `strcmp` function that implement's a `0.19ms` sleep for easier statistical measurements and to account for the load/amount of requests being handled by WSGI Asynch server. **Coming soon**
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
