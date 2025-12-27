/* Rexx */

/*-------------------------------------------------------------------*/
/* Generate a PKCS #11 ML-DSA key pair.                              */
/*-------------------------------------------------------------------*/

/* expected results */
ExpRC = '00000000'x ;
ExpRS = '00000000'x ;

Call TCSETUP

GKP_Handle             = Left('QSAFE.TEST.TOKEN',44)

GKP_PrivKey_Attr_List = '0005'x||,
       CKA_CLASS      ||'0004'x|| CKO_PRIVATE_KEY          ||,
       CKA_KEY_TYPE   ||'0004'x|| CKK_IBM_ML_DSA           ||,
       CKA_TOKEN      ||'0001'x|| CK_TRUE                  ||,
       CKA_SIGN       ||'0001'x|| CK_TRUE                  ||,
       CKA_IBM_SECURE ||'0001'x|| CK_TRUE

/*-------------------------------------------------------------------*/
/* Parameter set indicating the ML-DSA strength can be set to the    */
/* following options:                                                */
/*     CKP_IBM_ML_DSA_44                                             */
/*     CKP_IBM_ML_DSA_65                                             */
/*     CKP_IBM_ML_DSA_87                                             */
/*-------------------------------------------------------------------*/
GKP_PubKey_Attr_List = '0005'x||,
       CKA_CLASS              ||'0004'x|| CKO_PUBLIC_KEY    ||,
       CKA_KEY_TYPE           ||'0004'x|| CKK_IBM_ML_DSA    ||,
       CKA_TOKEN              ||'0001'x|| CK_TRUE           ||,
       CKA_VERIFY             ||'0001'x|| CK_TRUE           ||,
       CKA_IBM_PARAMETER_SET  ||'0004'x|| CKP_IBM_ML_DSA_44

Call CSFPGKP;

Exit
/* --------------------------------------------------------------- */
/* PKCS #11 Generate Key Pair                                      */
/* Use the PKCS #11 Generate Key Pair callable service to generate */
/* an RSA, DSA, Elliptic Curve, Diffie-Hellman, Dilithium (LI2),   */
/* Kyber, ML-DSA, or ML-KEM key pair.                              */
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

CKK_IBM_ML_DSA         = '80010025'X;
CKP_IBM_ML_DSA_44      = '00000001'X;
CKP_IBM_ML_DSA_65      = '00000002'X;
CKP_IBM_ML_DSA_87      = '00000003'X;

CKO_PUBLIC_KEY         = '00000002'X
CKO_PRIVATE_KEY        = '00000003'X

CKA_IBM_SECURE         = '80000006'X
CKA_KEY_TYPE           = '00000100'X
CKA_CLASS              = '00000000'X
CKA_TOKEN              = '00000001'X
CKA_IBM_PARAMETER_SET  = '80010010'X;
CKA_SIGN               = '00000108'X;
CKA_VERIFY             = '0000010A'X;

CK_TRUE                = '01'x
CK_FALSE               = '00'x
Return

EXIT; 