/* Rexx */

/*-------------------------------------------------------------------*/
/* EP11 Hybrid Signature scheme using ECDSA for the primary          */
/* signature and CRYSTALS-Dilithium for the secondary signature      */
/*-------------------------------------------------------------------*/

/* expected results */
ExpRC = '00000000'x ;
ExpRS = '00000000'x ;

/* Message to Sign */
message =  'A9993E364706816ABA3E25717850C26C9CD0D89D'X; 

Call TCSetup
/*-------------------------------------------------------------------*/
/* Generate a PKCS #11 Token                                         */
/*-------------------------------------------------------------------*/

Token_Handle     = left('QSAFE.SIGNATURE.TOKEN',44) 

Call CSFPTRC


/*-------------------------------------------------------------------*/
/* Generate a PKCS #11 ECC key pair                                  */
/*-------------------------------------------------------------------*/

GKP_Handle             = Token_Handle

GKP_PrivKey_Attr_List = '0005'x||,
       CKA_CLASS      ||'0004'x|| CKO_PRIVATE_KEY          ||,
       CKA_KEY_TYPE   ||'0004'x|| CKK_EC                   ||,
       CKA_TOKEN      ||'0001'x|| CK_TRUE                  ||,
       CKA_SIGN       ||'0001'x|| CK_TRUE                  ||,
       CKA_IBM_SECURE ||'0001'x|| CK_TRUE

GKP_PubKey_Attr_List = '0005'x||,
       CKA_CLASS              ||'0004'x|| CKO_PUBLIC_KEY    ||,
       CKA_KEY_TYPE           ||'0004'x|| CKK_EC            ||,
       CKA_TOKEN              ||'0001'x|| CK_TRUE           ||,
       CKA_EC_PARAMS          || D2C(LENGTH(secp521r1),2)   ||,
                                      secp521r1             ||,
       CKA_VERIFY             ||'0001'x|| CK_TRUE

Call CSFPGKP;

ECC_Pubkey_handle = GKP_PubKey_Handle

ECC_PrivKey_Handle = GKP_PrivKey_Handle


/*-------------------------------------------------------------------*/
/* Generate a PKCS #11 Dilithium key pair                            */
/*-------------------------------------------------------------------*/

GKP_Handle             = Token_Handle

GKP_PrivKey_Attr_List = '0005'x||,
       CKA_CLASS      ||'0004'x|| CKO_PRIVATE_KEY          ||,
       CKA_KEY_TYPE   ||'0004'x|| CKK_IBM_DILITHIUM        ||,
       CKA_TOKEN      ||'0001'x|| CK_TRUE                  ||,
       CKA_SIGN       ||'0001'x|| CK_TRUE                  ||,
       CKA_IBM_SECURE ||'0001'x|| CK_TRUE

GKP_PubKey_Attr_List = '0005'x||,
       CKA_CLASS              ||'0004'x|| CKO_PUBLIC_KEY    ||,
       CKA_KEY_TYPE           ||'0004'x|| CKK_IBM_DILITHIUM ||,
       CKA_IBM_DILITHIUM_MODE ||'000D'x|| DER_OID_6_5_R2    ||,
       CKA_TOKEN              ||'0001'x|| CK_TRUE           ||,
       CKA_VERIFY             ||'0001'x|| CK_TRUE

Call CSFPGKP;

LI2_Pubkey_handle = GKP_PubKey_Handle

LI2_PrivKey_Handle = GKP_PrivKey_Handle

/*------------------------------------------------------------------*/
/* Call the CSFPPKS service passing the ECC private                 */
/* key handle to generate the primary digital signature.            */
/*------------------------------------------------------------------*/
 PKS_Rule_Array          = 'ECDSA   '
 PKS_Key_Handle          = ECC_PrivKey_Handle
 PKS_Cipher_Value        = message


 Call CSFPPKS

 ECC_sig = PKS_Clear_Value

/*------------------------------------------------------------------*/
/* Call the CSFPPKS service passing the CRYSTALS-Dilithium private  */
/* key handle to generate the secondary digital signature.          */
/*------------------------------------------------------------------*/
 PKS_Rule_Array          = 'LI2     '
 PKS_Key_Handle          = LI2_PrivKey_Handle
 PKS_Cipher_Value        = message


 Call CSFPPKS

 Dilithium_sig = PKS_Clear_Value

/*------------------------------------------------------------------*/
/* Call the CSFPPKV service passing the ECC public                  */
/* key handle to verify the primary digital signature.              */
/*------------------------------------------------------------------*/
 PKV_Rule_Array          = 'ECDSA   '
 PKV_Key_Handle          = ECC_Pubkey_handle
 PKV_Cipher_Value        = message
 PKV_Clear_Value         = ECC_sig

 Call CSFPPKV

/*------------------------------------------------------------------*/
/* Call the CSFPPKV service passing the CRYSTALS-Dilithium public   */
/* key handle to verify the secondary digital signature.            */
/*------------------------------------------------------------------*/
 PKV_Rule_Array          = 'LI2     '
 PKV_Key_Handle          = LI2_Pubkey_handle
 PKV_Cipher_Value        = message
 PKV_Clear_Value         = Dilithium_sig

 Call CSFPPKV

/*-------------------------------------------------------------------*/
/* Delete a PKCS #11 Token                                           */
/*-------------------------------------------------------------------*/

TRD_Handle       = left(Token_Handle,44) ;

Call CSFPTRD


Exit

/* --------------------------------------------------------------- */
/* PKCS #11 Token Record Create                                    */
/* Intialize a z/OS PKCS #11 token                                 */           
/* --------------------------------------------------------------- */
CSFPTRC:

   TRC_AttrList          = ,
     'IBM Corporation - Manufacturer  ' ||,      /* 32 char Manuf ID */
     'Model# _'||'12345678'             ||,      /* 16 char Model    */
     'Serial#_'||'12345678'             ||,      /* 16 char Serial#  */
     '00000000'x;                                /*  4 char reserved */

   TRC_AttrListLength   = D2C( Length( TRC_AttrList ),4);

   TRC_RC           = 'FFFFFFFF'x ;
   TRC_RS           = 'FFFFFFFF'x ;
   TRC_Exit_Length  = '00000000'x ;
   TRC_Exit_Data    = '' ;
   TRC_Rule_Count   = '00000001'x;
   TRC_Rule_Array   = 'TOKEN   ' ;
   TRC_Handle       = Token_Handle ;

   /* call Token Record Create */
   address linkpgm 'CSFPTRC'                                   ,
                   'TRC_RC'              'TRC_RS'              ,
                   'TRC_Exit_Length'     'TRC_Exit_Data'       ,
                   'TRC_Handle'                                ,
                   'TRC_Rule_Count'      'TRC_Rule_Array'      ,
                   'TRC_AttrListLength'  'TRC_AttrList'        ;

   if (TRC_RC = ExpRS ) & (TRC_RS = ExpRS ) Then
     say  'TRC successful - Token';
   else
     say  'TRC failed: rc =' c2x(TRC_rc) 'rs =' c2x(TRC_rs) ;

return;
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
/* PKCS #11 Token Record Delete                                    */
/* --------------------------------------------------------------- */
CSFPTRD:

   TRD_RC           = 'FFFFFFFF'x ;
   TRD_RS           = 'FFFFFFFF'x ;
   TRD_Exit_Length  = '00000000'x ;
   TRD_Exit_Data    = '' ;
   TRD_Rule_Count   = '00000001'x;
   TRD_Rule_Array   = 'TOKEN   ';

   /* call Token Record Delete */
   address linkpgm 'CSFPTRD'                                   ,
                   'TRD_RC'              'TRD_RS'              ,
                   'TRD_Exit_Length'     'TRD_Exit_Data'       ,
                   'TRD_Handle'                                ,
                   'TRD_Rule_Count'      'TRD_Rule_Array'      ;

   say 'TRD: rc =' c2x(TRD_rc) 'rs =' c2x(TRD_rs) ;

return;

/* --------------------------------------------------------------- */
/* PKCS #11 Private Key Sign                                       */
/*                                                                 */
/* Used to sign data using an ECC, RSA, DSA, or CRYSTALS-Dilithium */
/* private key.                                                    */
/* --------------------------------------------------------------- */
CSFPPKS:

 PKS_RC              = 'FFFFFFFF'x ;
 PKS_RS              = 'FFFFFFFF'x ;
 PKS_Exit_Length     = '00000000'x ;
 PKS_Exit_Data       = '' ;
 PKS_Clear_Value_length  = D2C(4596,4);
 PKS_Clear_Value         = Copies('00'x, C2D(PKS_Clear_Value_length) )
 PKS_Rule_Count = d2c( length(PKS_Rule_Array)/8,4 )
 PKS_Cipher_Value_Length = D2C( Length(PKS_Cipher_Value),4 );


 address linkpgm 'CSFPPKS'                 ,
                 'PKS_rc'                  ,
                 'PKS_rs'                  ,
                 'PKS_Exit_Length'         ,
                 'PKS_Exit_Data'           ,
                 'PKS_Rule_Count'          ,
                 'PKS_Rule_Array'          ,
                 'PKS_Cipher_Value_Length' ,
                 'PKS_Cipher_Value'        ,
                 'PKS_Key_Handle'          ,
                 'PKS_Clear_Value_Length'  ,
                 'PKS_Clear_Value'         ;

 PKS_Clear_value = ,
    substr(PKS_clear_value,1,c2d(PKS_Clear_value_length))

 if (PKS_RC \= ExpRC | PKS_RS \= ExpRS) Then
    say 'PKS Failed : rc =' c2x(PKS_RC) 'rs =' c2x(PKS_RS) ;
 else
    say 'PKS Successful : rc =' c2x(PKS_RC) 'rs =' c2x(PKS_RS) ;
return;
/* --------------------------------------------------------------- */
/* PKCS #11 Public Key Verify                                      */
/*                                                                 */
/* Used to verify a signature using an ECC, RSA, DSA, or           */
/* CRYSTALS-Dilithium public key.                                  */
/* --------------------------------------------------------------- */
CSFPPKV:

 PKV_RC              = 'FFFFFFFF'x ;
 PKV_RS              = 'FFFFFFFF'x ;
 PKV_Exit_Length     = '00000000'x ;
 PKV_Exit_Data       = '';
 PKV_Cipher_Value_length = D2C( Length(PKV_Cipher_Value),4 );
 PKV_Clear_Value_length  = D2C( Length(PKV_Clear_Value),4 );
 PKV_Rule_Count      = d2c( length(PKV_rule_Array)/8,4 )


 address linkpgm 'CSFPPKV'             ,
                 'PKV_RC'              ,
                 'PKV_RS'              ,
                 'PKV_Exit_Length'     ,
                 'PKV_Exit_Data'       ,
                 'PKV_Rule_Count'      ,
                 'PKV_Rule_Array'      ,
                 'PKV_Clear_Value_Length' ,
                 'PKV_Clear_Value'      ,
                 'PKV_Key_Handle'       ,
                 'PKV_Cipher_Value_length' ,
                 'PKV_Cipher_Value'     ;

 PKV_Cipher_value = ,
    substr(pkv_cipher_value,1,c2d(PKV_Cipher_value_length))

 if (PKV_RC \= ExpRC | PKV_RS \= ExpRS) Then
   say 'PKV Failed : rc =' c2x(PKV_RC) 'rs =' c2x(PKV_RS) ;
 else
   say 'PKV successful : rc =' c2x(PKV_RC) 'rs =' c2x(PKV_RS) ;

return; 

/* --------------------------------------------------------------- */
/*                                                                 */
/* --------------------------------------------------------------- */
TCSetup:
CKO_PUBLIC_KEY         = '00000002'X
CKO_PRIVATE_KEY        = '00000003'X
CKA_IBM_SECURE         = '80000006'X
CKA_KEY_TYPE           = '00000100'X
CKA_CLASS              = '00000000'X
CKA_TOKEN              = '00000001'X
CKA_SIGN               = '00000108'X;
CKA_VERIFY             = '0000010A'X;
CK_TRUE                = '01'x
CK_FALSE               = '00'x
secp521r1              = '06052b81040023'x
CKK_EC                 = '00000003'X
CKK_GENERIC_SECRET     = '00000010'X
CKO_PUBLIC_KEY         = '00000002'X
CKO_PRIVATE_KEY        = '00000003'X
CKO_SECRET_KEY         = '00000004'X
CKA_CLASS              = '00000000'X
CKA_TOKEN              = '00000001'X
CKA_LABEL              = '00000003'X
CKA_IBM_SECURE         = '80000006'X
CKA_EC_PARAMS          = '00000180'X
CKA_EC_POINT           = '00000181'X
CKA_VALUE_LEN          = '00000161'X
CKA_KEY_TYPE           = '00000100'X
CKA_IBM_DILITHIUM_MODE = '80000010'X
DER_OID_6_5_R2         = '060B2B0601040102820B010605'X
CKK_IBM_DILITHIUM      = '80010023'X
Return