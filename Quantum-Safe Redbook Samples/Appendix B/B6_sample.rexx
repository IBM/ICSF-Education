/* Rexx */

Call TCSetup

/*-------------------------------------------------------------------*/
/* Generate a secure PKCS #11 Kyber key pair                         */
/*-------------------------------------------------------------------*/

/* expected results */
ExpRC = '00000000'x ;
ExpRS = '00000000'x ;


GKP_Handle             = Left('QSAFE.TEST.TOKEN',44)

GKP_PrivKey_Attr_List = '0007'x||,
       CKA_CLASS      ||'0004'x|| CKO_PRIVATE_KEY          ||,
       CKA_KEY_TYPE   ||'0004'x|| CKK_IBM_KYBER            ||,
       CKA_TOKEN      ||'0001'x|| CK_TRUE                  ||,
       CKA_DERIVE     ||'0001'x|| CK_TRUE                  ||,
       CKA_DECRYPT    ||'0001'x|| CK_TRUE                  ||,
       CKA_UNWRAP     ||'0001'x|| CK_TRUE                  ||,
       CKA_IBM_SECURE ||'0001'x|| CK_TRUE

GKP_PubKey_Attr_List = '0007'x||,
       CKA_CLASS              ||'0004'x|| CKO_PUBLIC_KEY    ||,
       CKA_KEY_TYPE           ||'0004'x|| CKK_IBM_KYBER     ||,
       CKA_IBM_KYBER_MODE     ||'000D'x|| DER_OID_KYBER_1024_R2   ||,
       CKA_TOKEN              ||'0001'x|| CK_TRUE           ||,
       CKA_WRAP               ||'0001'x|| CK_TRUE           ||,
       CKA_DERIVE             ||'0001'x|| CK_TRUE           ||,
       CKA_ENCRYPT            ||'0001'x|| CK_TRUE

Call CSFPGKP;

Exit
/* --------------------------------------------------------------- */
/* PKCS #11 Generate Key Pair                                      */
/* Use the PKCS #11 Generate Key Pair callable service to generate */
/* an RSA, DSA, Elliptic Curve, Diffie-Hellman, Dilithium (LI2) or */
/* Kyber key pair.                                                 */
/*                                                                 */
/* See the ICSF Application Programmer's Guide for more details.   */
/* --------------------------------------------------------------- */
CSFPGKP:
 GKP_RC = 'FFFFFFFF'x
 GKP_RS = 'FFFFFFFF'x
 GKP_Exit_Length = '00000000'x
 GKP_Exit_Data = ''
 GKP_Rule_Count = '00000000'x
 GKP_Rule_Array = ''
 GKP_PubKey_Handle = copies(' ',44)
 GKP_PrivKey_Handle = copies(' ',44)

 GKP_PubKey_Attr_List_Length = D2C(Length(GKP_PubKey_Attr_List),4)
 GKP_PrivKey_Attr_List_Length = D2C(Length(GKP_PrivKey_Attr_List),4)

 address linkpgm 'CSFPGKP',
                 'GKP_RC' 'GKP_RS',
                 'GKP_Exit_Length' 'GKP_Exit_Data',
                 'GKP_Handle',
                 'GKP_Rule_Count' 'GKP_Rule_Array',
                 'GKP_PubKey_Attr_List_Length',
                 'GKP_PubKey_Attr_List',
                 'GKP_PubKey_Handle',
                 'GKP_PrivKey_Attr_List_Length',
                 'GKP_PrivKey_Attr_List',
                 'GKP_PrivKey_Handle'

   if (GKP_RC \= ExpRC | GKP_RS \= ExpRS) Then
     say 'GKP failed: rc =' c2x(GKP_rc) 'rs =' c2x(GKP_rs) ;
   else
     say 'GKP successful : rc =' c2x(GKP_rc) 'rs =' c2x(GKP_rs) ;

return;

/* --------------------------------------------------------------- */
/*                                                                 */
/* --------------------------------------------------------------- */
TCSetup:

DER_OID_KYBER_1024_R2 = '060B2B0601040102820B050404'X;

CKK_IBM_KYBER         = '80010024'X;

CKO_PUBLIC_KEY        = '00000002'X
CKO_PRIVATE_KEY       = '00000003'X

CKA_IBM_SECURE        = '80000006'X
CKA_KEY_TYPE          = '00000100'X
CKA_CLASS             = '00000000'X
CKA_TOKEN             = '00000001'X
CKA_IBM_KYBER_MODE    = '8000000E'X;
CKA_ENCRYPT           = '00000104'X;
CKA_DECRYPT           = '00000105'X;
CKA_WRAP              = '00000106'X;
CKA_UNWRAP            = '00000107'X;
CKA_DERIVE            = '0000010C'X;

CK_TRUE               = '01'x
CK_FALSE              = '00'x

Return

EXIT; 