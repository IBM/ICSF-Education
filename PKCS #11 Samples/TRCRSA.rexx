 /* Rexx */

/*-------------------------------------------------------------------*/
/* Create an RSA Public TKDS object using known key parts            */
/*-------------------------------------------------------------------*/

call TCSETUP


/* Fill in TKDS Token handle */
TKDS_Token = Left('',44)

/* Set the values of the known clear key parts */

pubkey_modulus_len = ''x
pubkey_modulus = ''x
pubkey_pubexp_len = ''x
pubkey_pubexp = ''x

 
 TRC_AttrList    = '0007'x||,                /* number attributes */
   CKA_CLASS          ||'0004'x || CKO_PUBLIC_KEY      ||,          
   CKA_KEY_TYPE       ||'0004'x || CKK_RSA ||,     
   CKA_MODULUS        ||pubkey_modulus_len|| pubkey_modulus ||,        
   CKA_PUBLIC_EXPONENT||pubkey_pubexp_len || pubkey_pubexp ||,         
   CKA_TOKEN          ||'0001'x||CK_TRUE ||,
   CKA_IBM_SECURE     ||'0001'x|| CK_TRUE  ||,
   CKA_VERIFY         ||'0001'x|| CK_TRUE         


  call TRC_Object;


 Exit

/*-------------------------------------------------------------------*/
/* PKCS #11 Token Record Create                                      */
/*-------------------------------------------------------------------*/
 TRC_Object:
           
 TRC_AttrListLength   = D2C( Length( TRC_AttrList ),4);
 
 TRC_RC           = 'FFFFFFFF'x ;
 TRC_RS           = 'FFFFFFFF'x ;
 TRC_Exit_Length  = '00000000'x ;
 TRC_Exit_Data    = '' ;
 TRC_Rule_Count   = '00000001'x;
 TRC_Rule_Array   = 'OBJECT  ' ;
 TRC_Handle       = Left(TKDS_Token,44) ;
 
 /* call Token Record Create */
 address linkpgm 'CSFPTRC'                                   ,
                 'TRC_RC'              'TRC_RS'              ,
                 'TRC_Exit_Length'     'TRC_Exit_Data'       ,
                 'TRC_Handle'                                ,
                 'TRC_Rule_Count'      'TRC_Rule_Array'      ,
                 'TRC_AttrListLength'  'TRC_AttrList'        ;
 
 say 'TRC: rc =' c2x(TRC_rc) 'rs =' c2x(TRC_rs)       
 
return;

TCSETUP:

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

CKK_RSA                 = '00000000'X;
CKA_MODULUS_BITS        = '00000121'X;
CKA_PUBLIC_EXPONENT     = '00000122'X;
CKA_MODULUS             = '00000120'X;

CKO_PUBLIC_KEY = '00000002'X
CKO_PRIVATE_KEY = '00000003'X
CKA_CLASS = '00000000'X
CKA_TOKEN = '00000001'X

CKA_LABEL = '00000003'X
CKA_VALUE_LEN = '00000161'X

Return