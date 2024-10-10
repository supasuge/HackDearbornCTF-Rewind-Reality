from enigmapython.EnigmaM3RotorI import EnigmaM3RotorI
from enigmapython.EnigmaM3RotorII import EnigmaM3RotorII
from enigmapython.EnigmaM3RotorIII import EnigmaM3RotorIII
from enigmapython.ReflectorUKWB import ReflectorUKWB
from enigmapython.PlugboardPassthrough import PlugboardPassthrough
from enigmapython.EnigmaM3 import EnigmaM3
from enigmapython.EtwPassthrough import EtwPassthrough
import itertools
import sys

# idk y this isn't working ill try again l8er


known_prefix = "hdthree"

def brute_force_enigma(ciphertext):
    # Rotor I and II positions (provided)
    rotor1 = EnigmaM3RotorI(1, 17)  # Rotor I position 17
    rotor2 = EnigmaM3RotorII(1, 1)   # Rotor II position 1
    reflector = ReflectorUKWB()      # Reflector B
    plugboard = PlugboardPassthrough()  # No plugboard swapping
    etwM3 = EtwPassthrough()
    # Brute-force rotor III's initial position (from 'A' to 'Z')
    for rotor3_position in range(1, 27):  # Positions 1 to 26 correspond to A-Z
        rotor3 = EnigmaM3RotorIII(1, rotor3_position)

        # Setup the Enigma M3 machine
        enigmaM3 = EnigmaM3(plugboard, rotor3, rotor2, rotor1, reflector, etwM3, True)

        # Decrypt the ciphertext with the current rotor III position
        decrypted_message = enigmaM3.input_string(ciphertext)

        # Check if the decrypted message contains the known prefix
        if decrypted_message.startswith(known_prefix):
            print(f"Found rotor III position: {rotor3_position}")
            print(f"Decrypted message: {decrypted_message}")
            return decrypted_message

    return None

if __name__ == "__main__":
    # The ciphertext from the challenge (replace with actual value from encryption step)
    ciphertext = "azjlfwqzciqtotuurvxhqdnqkspedmsfqnwheowp"

    # Start brute-forcing to find the correct rotor III position
    print(brute_force_enigma(ciphertext))
