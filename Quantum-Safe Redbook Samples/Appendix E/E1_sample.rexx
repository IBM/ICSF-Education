/* Rexx */

/*-------------------------------------------------------------------*/
/* CCA Hybrid Quantum-safe Key exchange scheme                       */
/*-------------------------------------------------------------------*/
/* PKE will require ACP '0083'x                                      */
/* EDH will require ACP '035D'x                                      */
/*-------------------------------------------------------------------*/

CALL INITIALIZE

/* expected results */
Exp_rc = '00000000'x ;
Exp_rs = '00000000'x

/* global parameters */
exit_data_length = '00000000'x
exit_data = ''

/* PKB parameters */
private_name    = ''
user_assoc_data = ''

/* PKE parameters */
PKE_rule_array = 'ZERO-PAD'
PKE_keyvalue       = ''
sym_key_identifier = ''

/* KYT2 parameters */
kek_identifier = ''

/*---------------------*/
/* Create ALICE's keys */
/*---------------------*/

Say "Generating Alice's ML-KEM key pair..."

/*-----------------------------------------------------------*/
/* Build ML-KEM skeleton token with U-DATENC key usage flag  */
/*-----------------------------------------------------------*/
PKB_rule_array = 'QSA-PAIR'||'U-DATENC'
kvs            = '06'x ||,   /* algorithm identifier      */
                 '00'x ||,   /* clear key format skeleton */
                 '1024'x ||, /* algorithm parameter       */
                 '0000'x ||, /* clear key length          */
                 '0000'x     /* reserved                  */
CALL CSNDPKB

/*-----------------------------------------------------------*/
/* Generate ML-KEM key pair using built skeleton token       */
/*-----------------------------------------------------------*/
PKG_rule_array = 'master  '
CALL CSNDPKG

ALICE_MLKEM_pvt = PKG_token

/*-----------------------------------------------------------*/
/* Extract ML-KEM public key from ML-KEM private key token   */
/*-----------------------------------------------------------*/
PKX_source_key  = PKG_token
CALL CSNDPKX

ALICE_MLKEM_publ = PKX_token

/*-----------------------------------------------------------*/
/* Build ECC skeleton token with KEY-MGMT key usage flag     */
/*-----------------------------------------------------------*/
Say "Generating Alice's ECC key pair..."
PKB_rule_array = 'ECC-PAIR'||'KEY-MGMT'
kvs            = '00'x ||,   /* Prime curve    */
                 '00'x ||,   /* reserved       */
                 '0180'x ||, /* 384 bits       */
                 '0000'x ||, /* pvt key length */
                 '0000'x     /* pub key length */
CALL CSNDPKB

/*-----------------------------------------------------------*/
/* Generate ECC key pair using built skeleton token          */
/*-----------------------------------------------------------*/
PKG_rule_array = 'master  '
CALL CSNDPKG

ALICE_ECC_pvt  = PKG_token

/*-----------------------------------------------------------*/
/* Extract ECC public key from ECC private key token         */
/*-----------------------------------------------------------*/
PKX_source_key     = PKG_token
CALL CSNDPKX

ALICE_ECC_publ = PKX_token

/*-------------------*/
/* Create BOB's keys */
/*-------------------*/

/*-----------------------------------------------------------*/
/* Build ECC skeleton token with KEY-MGMT key usage flag     */
/*-----------------------------------------------------------*/
Say "Generating Bob's ECC key pair..."

PKB_rule_array = 'ECC-PAIR'||'KEY-MGMT'
kvs            = '00'x ||,   /* Prime curve    */
                 '00'x ||,   /* reserved       */
                 '0180'x ||, /* 384 bits       */
                 '0000'x ||, /* pvt key length */
                 '0000'x     /* pub key length */
CALL CSNDPKB

/*-----------------------------------------------------------*/
/* Generate ECC key pair using built skeleton token          */
/*-----------------------------------------------------------*/
PKG_rule_array = 'master  '
CALL CSNDPKG

BOB_ECC_pvt    = PKG_token

/*-----------------------------------------------------------*/
/* Extract ECC public key from ECC private key token         */
/*-----------------------------------------------------------*/
PKX_source_key     = PKG_token
CALL CSNDPKX

BOB_ECC_publ   = PKG_token

/*-----------------------------------------------------------*/
/* BOB creates the shared-key derivation input               */
/*-----------------------------------------------------------*/
PKE_rule_array = 'ZERO-PAD'||'RANDOM  ' || 'AES-ENC '
PKE_keyvalue       = '01010101010101010202020202020202'x||,
                     '00000000000000000000000000000000'x
sym_key_identifier = BOB_AES_CIPHER_key_token
public_key_identifier = ALICE_MLKEM_publ
CALL CSNDPKE

/*-----------------------------------------------------------*/
/* BOB completes the shared-key derivation                   */
/*-----------------------------------------------------------*/
MLKEM_enciphered_PKE_keyvalue = enciphered_PKE_keyvalue
sym_enciphered_PKE_keyvalue   = PKE_keyvalue

EDH_rule_array = 'DERIV01 '||'KEY-AES '||'QSA-ECDH'||'IHKEYAES'
private_key_identifier = BOB_ECC_pvt
private_kek_identifier = ''
public_key_identifier  = ALICE_ECC_publ
hybrid_key_identifier  = BOB_AES_CIPHER_key_token
party_identifier       = 'Party#Identifier'
key_bit_length         = d2c(192,4)
initialization_vector  = '01010101010101010202020202020202'x
hybrid_ciphertext      = sym_enciphered_PKE_keyvalue
output_kek_identifier  = ''
output_key_identifier  = AES_CIPHER_skeleton
CALL CSNDEDH

/*-----------------------------------------------------------*/
/* A Key check value (KCV) is computed over BOBs shared-key  */
/*-----------------------------------------------------------*/
KYT2_rule_array = 'AES     '||'GENERATE'||'CMACZERO' ;
key_identifier  = output_key_identifier
CALL CSNBKYT2
KYT2_kcv_BOB = KYT2_kcv

/*-----------------------------------------------------------*/
/* Alice completes the shared-key derivation                 */
/*-----------------------------------------------------------*/
EDH_rule_array = 'DERIV01 '||'KEY-AES '||'QSA-ECDH'||'IHKEYKYB'
private_key_identifier = ALICE_ECC_pvt
private_kek_identifier = ''
public_key_identifier  = BOB_ECC_publ
hybrid_key_identifier  = ALICE_MLKEM_pvt
party_identifier       = 'Party#Identifier'
key_bit_length         = d2c(192,4)
initialization_vector  = ''
hybrid_ciphertext      = MLKEM_enciphered_PKE_keyvalue
output_kek_identifier  = ''
output_key_identifier  = AES_CIPHER_skeleton
CALL CSNDEDH
/*-----------------------------------------------------------*/
/* A Key check value (KCV) is computed over Alice's          */
/* shared-key                                                */
/*-----------------------------------------------------------*/
key_identifier  = output_key_identifier
CALL CSNBKYT2
KYT2_kcv_ALICE = KYT2_kcv

/*-----------------------------------------------------------*/
/* Verify that both Alice and Bobs shared-keys are identical */
/*-----------------------------------------------------------*/
IF KYT2_kcv_ALICE = KYT2_kcv_BOB THEN SAY 'TESTCASE SUCCESSFUL'

Exit;
/*------------------------------------------------------------------*/
/* PKA Key Token Build - used to create PKA key tokens.             */
/*                                                                  */
/* See the ICSF Application Programmer's Guide for more details.    */
/*------------------------------------------------------------------*/
CSNDPKB:

PKB_rc                 = 'FFFFFFFF'x
PKB_rs                 = 'FFFFFFFF'x
exit_data_length       = '00000000'x
exit_data              = ''
PKB_rule_count         = d2c(length(PKB_rule_array)/8,4)
kvs_length             = d2c(length(kvs),4)
private_name_length    = d2c(length(private_name),4)
user_assoc_data_length = d2c(length(user_assoc_data),4)
key_deriv_data_length  = '00000000'x  /* valid only with ECC-VER1 */
key_deriv_data         = ''
reserved_field3_length = '00000000'x
reserved_field3        = ''
reserved_field4_length = '00000000'x
reserved_field4        = ''
reserved_field5_length = '00000000'x
reserved_field5        = ''
PKB_token_length       = d2c(6500,4)  /* max */
PKB_token              = d2c(0,6500)

ADDRESS LINKPGM 'CSNDPKB' ,
                'PKB_rc'                 'PKB_rs' ,
                'exit_data_length'       'exit_data' ,
                'PKB_rule_count'         'PKB_rule_array' ,
                'kvs_length'             'kvs' ,
                'private_name_length'    'private_name' ,
                'user_assoc_data_length' 'user_assoc_data' ,
                'key_deriv_data_length'  'key_deriv_data' ,
                'reserved_field3_length' 'reserved_field3' ,
                'reserved_field4_length' 'reserved_field4' ,
                'reserved_field5_length' 'reserved_field5' ,
                'PKB_token_length'       'PKB_token'

IF PKB_rc \= Exp_rc | PKB_rs \= Exp_rs THEN
  SAY 'PKB FAILED rc =' c2x(PKB_rc) 'rs =' c2x(PKB_rs)
ELSE
 DO
  SAY 'PKB successful: rc =' c2x(PKB_rc) 'rs =' c2x(PKB_rs)
  PKB_token = SUBSTR(PKB_token,1,c2d(PKB_token_length))
 END

SAY
RETURN

/* --------------------------------------------------------------- */
/* PKA Key Generate  - Used to generate PKA key pairs.             */
/*                                                                 */
/* See the ICSF Application Programmer's Guide for more details.   */
/* --------------------------------------------------------------- */
CSNDPKG:

PKG_rc                   = 'FFFFFFFF'x ;
PKG_rs                   = 'FFFFFFFF'x ;
PKG_rule_count           = d2c(length(PKG_rule_array)/8,4) ;
regeneration_data_length = '00000000'x ;
regeneration_data        = '' ;
skeleton_key_id_length   = PKB_token_length ;
skeleton_key_id          = PKB_token ;
transport_key_id         = d2c(0,64) ;
PKG_token_length         = d2c(6500,4) ;
PKG_token                = copies('00'x,6500) ;

ADDRESS LINKPGM 'CSNDPKG' ,
                'PKG_rc'                   'PKG_rs' ,
                'exit_data_length'         'exit_data' ,
                'PKG_rule_count'           'PKG_rule_array' ,
                'regeneration_data_length' 'regeneration_data' ,
                'skeleton_key_id_length'   'skeleton_key_id' ,
                'transport_key_id' ,
                'PKG_token_length'         'PKG_token'

IF PKG_rc \= Exp_rc | PKG_rs \= Exp_rs THEN
  SAY 'PKG FAILED rc =' c2x(PKG_rc) 'rs =' c2x(PKG_rs)
ELSE
 DO
  SAY 'PKG successful: rc =' c2x(PKG_rc) 'rs =' c2x(PKG_rs)
  PKG_token = SUBSTR(PKG_token,1,c2d(PKG_token_length))
 END

SAY
RETURN

/*------------------------------------------------------------------*/
/* PKA Public Key Extract                                           */
/*                                                                  */
/* Extracts a PKA public key token from a PKA internal (operational)*/
/* or external (importable) private key token.                      */
/*                                                                  */
/* See the ICSF Application Programmer's Guide for more details.    */
/*------------------------------------------------------------------*/
CSNDPKX:

PKX_rc               = 'FFFFFFFF'x ;
PKX_rs               = 'FFFFFFFF'x ;
PKX_rule_array_count = '00000000'x ;
PKX_rule_array       = '' ;
PKX_source_key_length    = d2c(length(PKX_source_key),4) ;
PKX_token_length     = d2c(6500,4) ;
PKX_token            = copies('00'x,6500) ;

ADDRESS LINKPGM 'CSNDPKX' ,
                'PKX_rc' ,
                'PKX_rs' ,
                'exit_data_length' ,
                'exit_data' ,
                'PKX_rule_array_count' ,
                'PKX_rule_array' ,
                'PKX_source_key_length' ,
                'PKX_source_key' ,
                'PKX_token_length' ,
                'PKX_token'

IF PKX_rc /= Exp_rc | PKX_rs /= Exp_rs THEN
 DO ;
  SAY 'PKX FAILED rc =' c2x(PKX_rc) 'rs =' c2x(PKX_rs)
 END ;
ELSE
 DO ;
   SAY 'PKX successful: rc =' c2x(PKX_rc) 'rs =' c2x(PKX_rs)
   PKX_token = ,
     SUBSTR(PKX_token,1,c2d(PKX_token_length))
 END
SAY
RETURN

/* ---------------------------------------------------------------- */
/* PKA Encrypt                                                      */
/*                                                                  */
/* Creates and encrypts derivation input                            */
/*                                                                  */
/* See the ICSF Application Programmer's Guide for more details.    */
/* ---------------------------------------------------------------- */
CSNDPKE:

PKE_rc = 'FFFFFFFF'x
PKE_rs = 'FFFFFFFF'x
exit_data_length = '00000000'x
exit_data = ''
PKE_rule_array_count = d2c(length(PKE_rule_array)/8,4)
PKE_keyvalue_length      = d2c(length(PKE_keyvalue),4)
sym_key_identifier_length = d2c(length(sym_key_identifier),4)
public_key_identifier_length = d2c(length(public_key_identifier),4)
enciphered_PKE_keyvalue_length = d2c(1568,4)
enciphered_PKE_keyvalue = d2c(0,1568)

say 'enciphered_PKE_keyvalue_length' c2x(enciphered_PKE_keyvalue_length)
say 'public_key_identifier_length' c2x(public_key_identifier_length)
say 'sym_key_identifier_length' c2x(sym_key_identifier_length)
say 'PKE_keyvalue_length' c2x(PKE_keyvalue_length)

ADDRESS LINKPGM 'CSNDPKE' ,
                'PKE_rc' ,
                'PKE_rs' ,
                'exit_data_length' ,
                'exit_data' ,
                'PKE_rule_array_count' ,
                'PKE_rule_array' ,
                'PKE_keyvalue_length' ,
                'PKE_keyvalue' ,
                'sym_key_identifier_length' ,
                'sym_key_identifier' ,
                'public_key_identifier_length' ,
                'public_key_identifier' ,
                'enciphered_PKE_keyvalue_length' ,
                'enciphered_PKE_keyvalue' ;

IF PKE_rc /= Exp_rc | PKE_rs /= Exp_rs THEN
  SAY 'PKE FAILED rc=' c2x(PKE_rc) 'rs =' c2x(PKE_rs) ;
ELSE
 DO
  enciphered_PKE_keyvalue = ,
     substr(enciphered_PKE_keyvalue,1,c2d(enciphered_PKE_keyvalue_length))
  SAY 'PKE successful rc=' c2x(PKE_rc) 'rs =' c2x(PKE_rs) ;
 END
SAY
RETURN

/* ---------------------------------------------------------------- */
/* ECC Diffie-Hellman                                               */
/*                                                                  */
/* Generates Z value from D-H process. Derives the shared-key using */
/* Z and rand-32 from PKE.                                          */
/*                                                                  */
/* See the ICSF Application Programmer's Guide for more details.    */
/* -----------------------------------------------------------------*/
CSNDEDH:

EDH_rc = 'FFFFFFFF'x
EDH_rs = 'FFFFFFFF'x
exit_data_length = '00000000'x
exit_data = ''
EDH_rule_array_count = d2c(length(EDH_rule_array)/8,4)
private_key_identifier_length = d2c(length(private_key_identifier),4)
private_kek_identifier_length = d2c(length(private_kek_identifier),4)
public_key_identifier_length  = d2c(length(public_key_identifier),4)
hybrid_key_identifier_length  = d2c(length(hybrid_key_identifier),4)
party_identifier_length       = d2c(length(party_identifier),4)
initialization_vector_length  = d2c(length(initialization_vector),4)
hybrid_ciphertext_length      = d2c(length(hybrid_ciphertext),4)
reserved3_length = '00000000'x
reserved3 = ''
reserved4_length = '00000000'x
reserved4 = ''
reserved5_length = '00000000'x
reserved5 = ''
output_kek_identifier_length  = d2c(length(output_kek_identifier),4)
output_key_identifier_length  = d2c(900,4)
output_key_identifier         = left(output_key_identifier,900)

ADDRESS LINKPGM 'CSNDEDH' ,
                'EDH_rc' ,
                'EDH_rs' ,
                'exit_data_length' ,
                'exit_data' ,
                'EDH_rule_array_count' ,
                'EDH_rule_array' ,
                'private_key_identifier_length' ,
                'private_key_identifier' ,
                'private_kek_identifier_length' ,
                'private_kek_identifier' ,
                'public_key_identifier_length' ,
                'public_key_identifier' ,
                'hybrid_key_identifier_length' ,
                'hybrid_key_identifier' ,
                'party_identifier_length' ,
                'party_identifier' ,
                'key_bit_length' ,
                'initialization_vector_length' ,
                'initialization_vector' ,
                'hybrid_ciphertext_length' ,
                'hybrid_ciphertext' ,
                'reserved3_length' ,
                'reserved3' ,
                'reserved4_length' ,
                'reserved4' ,
                'reserved5_length' ,
                'reserved5' ,
                'output_kek_identifier_length' ,
                'output_kek_identifier' ,
                'output_key_identifier_length' ,
                'output_key_identifier' ;

IF EDH_rc /= Exp_rc | EDH_rs /= Exp_rs THEN
  SAY 'EDH FAILED rc =' c2x(EDH_rc) 'rs =' c2x(EDH_rs)
ELSE
 DO
  SAY 'EDH successful: rc =' c2x(EDH_rc) 'rs =' c2x(EDH_rs)
  output_key_identifier = ,
     substr(output_key_identifier,1,c2d(output_key_identifier_length))
 END
SAY
RETURN

/*-------------------------------------------------------------------*/
/* Key Test2                                                         */
/*                                                                   */
/* Generate or verify a secure, cryptographic verification pattern   */
/* (also referred to as a key check value) for AES, DES and HMAC     */
/* keys.                                                             */
/*-------------------------------------------------------------------*/
CSNBKYT2:

KYT2_rc = 'FFFFFFFF'x ;
KYT2_rs = 'FFFFFFFF'x ;
KYT2_rule_array_count = d2c(length(KYT2_rule_array)/8,4) ;
key_identifier_length = d2c(length(key_identifier),4) ;
kek_identifier_length = d2c(length(kek_identifier),4) ;
reserved_length = d2c(0,4) ;
reserved        = '' ;
KYT2_kcv_length      = d2c(8,4) ;
KYT2_kcv             = d2c(0,c2d(KYT2_kcv_length)) ;

ADDRESS LINKPGM 'CSNBKYT2'                               ,
                'KYT2_rc'               'KYT2_rs'        ,
                'exit_data_length'      'exit_data'      ,
                'KYT2_rule_array_count' 'KYT2_rule_array',
                'key_identifier_length' 'key_identifier' ,
                'kek_identifier_length' 'kek_identifier' ,
                'reserved_length'       'reserved'       ,
                'KYT2_kcv_length'       'KYT2_kcv'       ;

IF KYT2_rc /= Exp_rc | KYT2_rs /= Exp_rs THEN
 SAY 'KYT2 failed: rc =' c2x(KYT2_rc) 'rs =' c2x(KYT2_rs) ;
ELSE
 SAY 'KYT2_kcv:' c2x(KYT2_kcv) ;

RETURN;

/* ----------------------------------------------------------------- */
INITIALIZE:

BOB_AES_CIPHER_key_token = ,
'010000DA0500000003012058C870E9D3194F0000000000000000020200000100'x||,
'007440001A0002400002000102C000000003E000000005054145532443495048'x||,
'4552233139324249544034332E32432E31362020202020202020202020202020'x||,
'202020202020202020202020202020202020202020202020C1C5E240C3C9D7C8'x||,
'C5D940F1F9F2C2C9E340F4F36DF2C36DF1F6E2219F0ED611C48D338927427F2D'x||,
'141BB9EA9B5B198C98E141BFDD0FFC7B403B8F68620E8744CC92E321354C0707'x||,
'A2CC1E32C835563FDB749C76FF3A0CB32DB0667FA1CA77E8F1B1'x

/* symmetric key skeletons */
AES_CIPHER_SKELETON = ,
'0100003805000000000000000000000000000000000000000000020200000100'x||,
'001A0000000000000002000102C000000003E00000000000'x

RETURN