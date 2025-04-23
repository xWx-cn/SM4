# SM4
## A Simple Coursework
In the software way, a block cipher algorithm - SM4 is implemented.    
You can directly use it.    
However,it provides low security level.So use it for experiment or something else that does not require high security level.
## Code Structure
### core
we have key_schedule/encrypt/decrypt modules, five work flows(ECB/CBC/CFB/OFB/CTR) modules and basic const in sm4.c：    
you can compile it only(make sure you write "main" at the bottom of the code), run it to see how sm4 works(you can also change the test function 'test_sm4()' to test more)     
### test method
to test it, we have bmp_crypt.c, it allows us to encrypt/decrypt a .bmp file and analyse it in bmp:    
(if you change the code yourself,run 'gcc -g bmp_crypt.c sm4.c -o bmp_crypt.exe' before you run this part)    
(in terminal)    
use it for encryption:' ./bmp_crypt.exe  e picture.bmp'    
use it for decryption:' ./bmp_crypt.exe  d'

