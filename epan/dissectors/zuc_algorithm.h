#ifndef __ZUC_ALGORITHM_H__
#define __ZUC_ALGORITHM_H__

typedef unsigned char u8;
typedef unsigned int  u32;

// Ciphering call
void zuc_f8(u8* CK,u32 COUNT,u32 BEARER,u32 DIRECTION,u32 LENGTH,u32* M,u32* C);


// Integrity call
void zuc_f9(u8* IK,u32 COUNT,u32 DIRECTION,u32 BEARER,u32 LENGTH,u32* M,u32* MAC);

#endif
