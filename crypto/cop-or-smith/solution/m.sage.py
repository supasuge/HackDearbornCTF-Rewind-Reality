

# This file was *autogenerated* from the file m.sage
from sage.all_cmdline import *   # import sage library

_sage_const_16 = Integer(16); _sage_const_2 = Integer(2); _sage_const_32332308151004740321270161371401779482629933250081757734598524562496477161204680894784549824667278078558086734945432732885203545490444272717812609145473170346737703306915184619801184010910835350302564374124974054995391665731536178034641894984420412533152266919470522212937561740201234390064552390119902987305854977134154649014242415085781627677160573776419356351702162042002112812791319450230935602408452814829529723015494108678896298255344340225987249009557720805693967586744275418046038586919636925605325756458305887683238626926001036007806958391030030435910443373846530580641386973618765354653655363625221470061928960149180 = Integer(32332308151004740321270161371401779482629933250081757734598524562496477161204680894784549824667278078558086734945432732885203545490444272717812609145473170346737703306915184619801184010910835350302564374124974054995391665731536178034641894984420412533152266919470522212937561740201234390064552390119902987305854977134154649014242415085781627677160573776419356351702162042002112812791319450230935602408452814829529723015494108678896298255344340225987249009557720805693967586744275418046038586919636925605325756458305887683238626926001036007806958391030030435910443373846530580641386973618765354653655363625221470061928960149180); _sage_const_12302880109777731579694015901024408759668209721287671911804219543370185229079350587454525467596442416727893439631241375365353119445154554944370787072754973895786153199307746770980290454449281685187862903634208621945795887220232851057185385095424972972205752015805246292845900149127234241407693850534344484408253307382543241817464988792029878986597599662945427372962257457142438455055182334487120803109625974952443268974931700576258647996245545394032590970812933662610480362140354007862460475950159177532733430385622071694992414609139450079989255019589536381126142601731561830001493272241831178319292334707268308076684367654673 = Integer(12302880109777731579694015901024408759668209721287671911804219543370185229079350587454525467596442416727893439631241375365353119445154554944370787072754973895786153199307746770980290454449281685187862903634208621945795887220232851057185385095424972972205752015805246292845900149127234241407693850534344484408253307382543241817464988792029878986597599662945427372962257457142438455055182334487120803109625974952443268974931700576258647996245545394032590970812933662610480362140354007862460475950159177532733430385622071694992414609139450079989255019589536381126142601731561830001493272241831178319292334707268308076684367654673); _sage_const_19958145637668326649010928240490139773351555479680728380032347851362607303785448088807150691078242360738218331515116334350201854779273823506142672702123607432804328508079712221008618751556613342622767381098010498911472437896350579747758111040865171655030268871338533096552497695592126861893683285535721495273863990822863466870360899551593899094760948975570772118388626427873597377243856567921895757452519029872265230753499869386032658032432637080529773774728055905220245440354232574827445406861384817046195022155029671851057361065814531157154740376698491661628249940131000223432987441125504290950975497567867004905577862828415 = Integer(19958145637668326649010928240490139773351555479680728380032347851362607303785448088807150691078242360738218331515116334350201854779273823506142672702123607432804328508079712221008618751556613342622767381098010498911472437896350579747758111040865171655030268871338533096552497695592126861893683285535721495273863990822863466870360899551593899094760948975570772118388626427873597377243856567921895757452519029872265230753499869386032658032432637080529773774728055905220245440354232574827445406861384817046195022155029671851057361065814531157154740376698491661628249940131000223432987441125504290950975497567867004905577862828415); _sage_const_65537 = Integer(65537)
from sage.all import *
from random import randint

# Function to convert string to long integer
def bytes_to_long(data):
    return int(data.encode().hex(), _sage_const_16 )

# Vise versa of above function
def long_to_bytes(data):
    return bytes.fromhex(hex(data)[_sage_const_2 :]).decode()

# Given ciphertexts
msg1 = _sage_const_32332308151004740321270161371401779482629933250081757734598524562496477161204680894784549824667278078558086734945432732885203545490444272717812609145473170346737703306915184619801184010910835350302564374124974054995391665731536178034641894984420412533152266919470522212937561740201234390064552390119902987305854977134154649014242415085781627677160573776419356351702162042002112812791319450230935602408452814829529723015494108678896298255344340225987249009557720805693967586744275418046038586919636925605325756458305887683238626926001036007806958391030030435910443373846530580641386973618765354653655363625221470061928960149180 
msg2 = _sage_const_12302880109777731579694015901024408759668209721287671911804219543370185229079350587454525467596442416727893439631241375365353119445154554944370787072754973895786153199307746770980290454449281685187862903634208621945795887220232851057185385095424972972205752015805246292845900149127234241407693850534344484408253307382543241817464988792029878986597599662945427372962257457142438455055182334487120803109625974952443268974931700576258647996245545394032590970812933662610480362140354007862460475950159177532733430385622071694992414609139450079989255019589536381126142601731561830001493272241831178319292334707268308076684367654673 
flag = _sage_const_19958145637668326649010928240490139773351555479680728380032347851362607303785448088807150691078242360738218331515116334350201854779273823506142672702123607432804328508079712221008618751556613342622767381098010498911472437896350579747758111040865171655030268871338533096552497695592126861893683285535721495273863990822863466870360899551593899094760948975570772118388626427873597377243856567921895757452519029872265230753499869386032658032432637080529773774728055905220245440354232574827445406861384817046195022155029671851057361065814531157154740376698491661628249940131000223432987441125504290950975497567867004905577862828415 
e = _sage_const_65537 

# Known plaintexts
m1 = bytes_to_long("Can't factor the modulus")
m2 = bytes_to_long("If you don't know the modulus... ;)")

# Compute n1 and n2
print("Computing m1^e and m2^e. Might take a little bit...")
n1 = m1**e - msg1
n2 = m2**e - msg2

# Compute N as gcd(n1, n2)
N = gcd(n1, n2)
print(f"Found N: {N}\n")

