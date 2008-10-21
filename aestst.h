/*
 ---------------------------------------------------------------------------
 Copyright (c) 2002, Dr Brian Gladman, Worcester, UK.   All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software in both source and binary
 form is allowed (with or without changes) provided that:

   1. distributions of this source code include the above copyright
      notice, this list of conditions and the following disclaimer;

   2. distributions in binary form include the above copyright
      notice, this list of conditions and the following disclaimer
      in the documentation and/or other associated materials;

   3. the copyright holder's name is not used to endorse products
      built using this software without specific written permission.

 ALTERNATIVELY, provided that this notice is retained in full, this product
 may be distributed under the terms of the GNU General Public License (GPL),
 in which case the provisions of the GPL apply INSTEAD OF those given above.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue 28/01/2004
*/

// The following definitions are required for testing only, They are not needed
// for AES (Rijndael) implementation.  They are used to allow C, C++ and DLL
// data access and subroutine calls to be expressed in the same form in the
// testing code.

#define ref_path    "..\\testvals\\"                // path for test vector files
#define out_path    "..\\outvals\\"                 // path for output files
#define dll_path    "..\\aes_dll\\release\\aes"     // path for DLL

#if defined(AES_CPP)

#define f_ectx              AESencrypt
#define f_enc_key128(a,b)   (a)->key128((b))
#define f_enc_key192(a,b)   (a)->key192((b))
#define f_enc_key256(a,b)   (a)->key256((b))
#define f_enc_key(a,b,c)    (a)->key((b),(c))
#define f_enc_blk(a,b,c)    (a)->encrypt((b),(c))

#define f_dctx              AESdecrypt
#define f_dec_key128(a,b)   (a)->key128((b))
#define f_dec_key192(a,b)   (a)->key192((b))
#define f_dec_key256(a,b)   (a)->key256((b))
#define f_dec_key(a,b,c)    (a)->key((b),(c))
#define f_dec_blk(a,b,c)    (a)->decrypt((b),(c))

#elif !defined(AES_DLL)

#define f_ectx              aes_encrypt_ctx
#define f_enc_key128(a,b)   aes_encrypt_key128((b),(a))
#define f_enc_key192(a,b)   aes_encrypt_key192((b),(a))
#define f_enc_key256(a,b)   aes_encrypt_key256((b),(a))
#define f_enc_key(a,b,c)    aes_encrypt_key((b),(c),(a))
#define f_enc_blk(a,b,c)    aes_encrypt((b),(c),(a))

#define f_dctx              aes_decrypt_ctx
#define f_dec_key128(a,b)   aes_decrypt_key128((b),(a))
#define f_dec_key192(a,b)   aes_decrypt_key192((b),(a))
#define f_dec_key256(a,b)   aes_decrypt_key256((b),(a))
#define f_dec_key(a,b,c)    aes_decrypt_key((b),(c),(a))
#define f_dec_blk(a,b,c)    aes_decrypt((b),(c),(a))

#define ek_name128          "aes_encrypt_key128"
#define ek_name192          "aes_encrypt_key192"
#define ek_name256          "aes_encrypt_key256"
#define ek_name             "aes_encrypt_key"
#define ec_name             "aes_encrypt"

#define dk_name128          "aes_decrypt_key128"
#define dk_name192          "aes_decrypt_key192"
#define dk_name256          "aes_decrypt_key256"
#define dk_name             "aes_decrypt_key"
#define dc_name             "aes_decrypt"

#else

#define f_ectx              aes_encrypt_ctx
#define f_dctx              aes_decrypt_ctx
typedef aes_rval g_enc_key(const unsigned char*, aes_encrypt_ctx[1]);
typedef aes_rval g_dec_key(const unsigned char*, aes_decrypt_ctx[1]);
typedef aes_rval g_enc_keyv(const unsigned char*, int, aes_encrypt_ctx[1]);
typedef aes_rval g_dec_keyv(const unsigned char*, int, aes_decrypt_ctx[1]);
typedef aes_rval g_enc_blk(const unsigned char*, unsigned char*, const aes_encrypt_ctx[1]);
typedef aes_rval g_dec_blk(const unsigned char*, unsigned char*, const aes_decrypt_ctx[1]);

typedef struct  // initialised with subroutine addresses when the DLL is loaded
{
    g_enc_key    *fn_enc_key128;
    g_enc_key    *fn_enc_key192;
    g_enc_key    *fn_enc_key256;
    g_enc_keyv   *fn_enc_key;
    g_enc_blk    *fn_enc_blk;
    g_dec_key    *fn_dec_key128;
    g_dec_key    *fn_dec_key192;
    g_dec_key    *fn_dec_key256;
    g_dec_keyv   *fn_dec_key;
    g_dec_blk    *fn_dec_blk;
} fn_ptrs;

#define f_dat(a,b)          (a->b)
#define f_enc_key128(a,b)   (fn.fn_enc_key128)((b),(a))
#define f_enc_key192(a,b)   (fn.fn_enc_key192)((b),(a))
#define f_enc_key256(a,b)   (fn.fn_enc_key256)((b),(a))
#define f_enc_key(a,b,c)    (fn.fn_enc_key)((b),(c),(a))
#define f_enc_blk(a,b,c)    (fn.fn_enc_blk)((b),(c),(a))
#define f_dec_key128(a,b)   (fn.fn_dec_key128)((b),(a))
#define f_dec_key192(a,b)   (fn.fn_dec_key192)((b),(a))
#define f_dec_key256(a,b)   (fn.fn_dec_key256)((b),(a))
#define f_dec_key(a,b,c)    (fn.fn_dec_key)((b),(c),(a))
#define f_dec_blk(a,b,c)    (fn.fn_dec_blk)((b),(c),(a))
#define ek_name128          "_aes_encrypt_key128@8"
#define ek_name192          "_aes_encrypt_key192@8"
#define ek_name256          "_aes_encrypt_key256@8"
#define ek_name             "_aes_encrypt_key@12"
#define ec_name             "_aes_encrypt@12"
#define dk_name128          "_aes_decrypt_key128@8"
#define dk_name192          "_aes_decrypt_key192@8"
#define dk_name256          "_aes_decrypt_key256@8"
#define dk_name             "_aes_decrypt_key@12"
#define dc_name             "_aes_decrypt@12"

#endif
