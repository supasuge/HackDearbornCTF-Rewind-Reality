from enigmapython.EtwPassthrough import EtwPassthrough
from enigmapython.EnigmaM3RotorI import EnigmaM3RotorI
from enigmapython.EnigmaM3RotorII import EnigmaM3RotorII
from enigmapython.EnigmaM3RotorIII import EnigmaM3RotorIII
from enigmapython.ReflectorUKWB import ReflectorUKWB
from enigmapython.PlugboardPassthrough import PlugboardPassthrough
from enigmapython.EnigmaM3 import EnigmaM3
import sys
import random


def encrypt_message():
    plugboardM3 = PlugboardPassthrough()
    rotor1_setting = random.randint(1, 26)
    rotor2_setting = random.randint(1, 26)
    rotor3_setting = random.randint(1, 26)

    rotor1M3 = EnigmaM3RotorI(1, rotor1_setting)
    rotor2M3 = EnigmaM3RotorII(1, rotor2_setting)
    rotor3M3 = EnigmaM3RotorIII(1, rotor3_setting)
    reflectorM3 = ReflectorUKWB()
    etwM3 = EtwPassthrough()
    enigmaM3 = EnigmaM3(plugboardM3, rotor3M3, rotor2M3, rotor1M3, reflectorM3, etwM3, True)


    ct = enigmaM3.input_string("hdthreeitsrainingaliensiminanumbrellabag")
    
    output = f"Note that '{' and '}' have been removed from the flag and is alphabetical only.\nCiphertext = {ct}\nRotors:\nI: {rotor1_setting}\nII: {rotor2_setting}\nIII: ???"
    open("output.txt", "w").write(output).close()


if __name__ == "__main__":
    encrypt_message()
