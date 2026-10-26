# c1bt_seed
- A pongo module that dumps hw 0x8a3/0x8a4 key and current krn.c1bt seed.  

Tested on A11, A12, A12Z, A13.  

## TL;DR
- AP shadow domain is configured:  
`cnch = BNCH = SHA384(AES128_CBC_ENC(K8a3, IV=0, zero_bytes[8] || LE64(BNCN)))[0:32]`  


- AP shadow domain is not configured:  
`cnch = SHA384(AES128_CBC_ENC(K8a4, IV=0, cryptex1_boot_seed[16]))[0:32]`  
