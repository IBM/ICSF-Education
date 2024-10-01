/* REXX */

/*********************************************************************/
/* PKCS #11 Hybrid Quantum-safe Key Exchange Scheme                  */
/*********************************************************************/
SIGNAL ON NOVALUE;

Call TCSETUP

/*********************************************************************/
/* Common test data                                                  */
/*********************************************************************/
/* expected results */
ExpRC = '00000000'x ;
ExpRS = '00000000'x ;

exit_data_length     = '00000000'X;
exit_data            = '';
GKP_EC_pub_attr_list =,
    '0006'X ||,
    CKA_CLASS              || '0004'X || CKO_PUBLIC_KEY            ||,
    CKA_KEY_TYPE           || '0004'X || CKK_EC                    ||,
    CKA_TOKEN              || '0001'X || CK_TRUE                   ||,
    CKA_IBM_SECURE         || '0001'X || CK_TRUE                   ||,
    CKA_EC_PARAMS          || D2C(LENGTH(secp521r1),2) ||,
                                         secp521r1                 ||,
    CKA_LABEL            /*|| 'llll'X || 'label'                  */ ;
GKP_EC_prv_attr_list =,
    '0005'X ||,
    CKA_CLASS              || '0004'X || CKO_PRIVATE_KEY           ||,
    CKA_KEY_TYPE           || '0004'X || CKK_EC                    ||,
    CKA_TOKEN              || '0001'X || CK_TRUE                   ||,
    CKA_IBM_SECURE         || '0001'X || CK_TRUE                   ||,
    CKA_LABEL            /*|| 'llll'X || 'label'                  */ ;
GKP_Kyber_pub_attr_list =,
    '0006'X ||,
    CKA_CLASS              || '0004'X || CKO_PUBLIC_KEY            ||,
    CKA_KEY_TYPE           || '0004'X || CKK_IBM_KYBER             ||,
    CKA_TOKEN              || '0001'X || CK_TRUE                   ||,
    CKA_IBM_SECURE         || '0001'X || CK_TRUE                   ||,
    CKA_IBM_KYBER_MODE     || D2C(LENGTH(DER_OID_KYBER_1024_R2),2) ||,
                                         DER_OID_KYBER_1024_R2     ||,
    CKA_LABEL            /*|| 'llll'X || 'label'                  */ ;
GKP_Kyber_prv_attr_list =,
    '0005'X ||,
    CKA_CLASS              || '0004'X || CKO_PRIVATE_KEY           ||,
    CKA_KEY_TYPE           || '0004'X || CKK_IBM_KYBER             ||,
    CKA_TOKEN              || '0001'X || CK_TRUE                   ||,
    CKA_IBM_SECURE         || '0001'X || CK_TRUE                   ||,
    CKA_LABEL            /*|| 'llll'X || 'label'                  */ ;
DVK_attr_list_ECDH =,
    '0004'X ||,
    CKA_CLASS              || '0004'X || CKO_SECRET_KEY            ||,
    CKA_IBM_SECURE         || '0001'X || CK_TRUE                   ||,
    CKA_KEY_TYPE           || '0004'X || CKK_GENERIC_SECRET        ||,
    CKA_VALUE_LEN          || '0004'X || '00000042'X               ;
DVK_attr_list_Kyber =,
    '0004'X ||,
    CKA_CLASS              || '0004'X || CKO_SECRET_KEY            ||,
    CKA_IBM_SECURE         || '0001'X || CK_TRUE                   ||,
    CKA_KEY_TYPE           || '0004'X || CKK_AES                   ||,
    CKA_VALUE_LEN          || '0004'X || '00000020'X               ;
known_clear_text = COPIES('A',16);

my_token = Left('QSAFE.TEST.TOKEN',44) /* Replace this token handle */


/*********************************************************************/
/* Step 1.1 Generate an ECC key pair for Alice                       */
/*********************************************************************/
testN = 'ECALICE';
pub_key_attr_list = GKP_EC_pub_attr_list||D2C(LENGTH(testN),2)||testN;
prv_key_attr_list = GKP_EC_prv_attr_list||D2C(LENGTH(testN),2)||testN;
CALL CSFPGKP;
handle_EC_Pub_A  = pub_key_object_handle;
handle_EC_Priv_A = prv_key_object_handle;

/*********************************************************************/
/* Step 2.2 Generate an ECC key pair for Bob                         */
/*********************************************************************/
testN = 'ECBOB';
pub_key_attr_list = GKP_EC_pub_attr_list||D2C(LENGTH(testN),2)||testN;
prv_key_attr_list = GKP_EC_prv_attr_list||D2C(LENGTH(testN),2)||testN;
CALL CSFPGKP;
handle_EC_Pub_B  = pub_key_object_handle;
handle_EC_Priv_B = prv_key_object_handle;

/*********************************************************************/
/* Step 2.2 Generate a Kyber key pair for Bob                        */
/*********************************************************************/
testN = 'QSBOB';
pub_key_attr_list=GKP_Kyber_pub_attr_list||D2C(LENGTH(testN),2)||testN;
prv_key_attr_list=GKP_Kyber_prv_attr_list||D2C(LENGTH(testN),2)||testN;
CALL CSFPGKP;
handle_Kyb_Pub_B  = pub_key_object_handle;
handle_Kyb_Priv_B = prv_key_object_handle;


/*********************************************************************/
/* Step 2.3 Derive a key using ECDH(HYBRID_NULL) with Bob's Private  */
/* ECC key and Alice Public ECC key                                  */
/*********************************************************************/
testN = 'DRVGENSECB';
pub_EC_POINT = CSFPGAV(handle_EC_Pub_A,CKA_EC_POINT);
rule_array                = 'EC-DH   ';
attribute_list            = DVK_attr_list_ECDH;
base_key_handle           = handle_EC_Priv_B;
DVK_ParmsList                =,
       CKD_IBM_HYBRID_NULL          ||, /* KDF function code      */
       '00000000'X                  ||, /* Optional data length   */
       '0000000000000000'X          ||, /* Optional data address  */
       D2C(LENGTH(pub_EC_POINT),4)  ||, /* Public value length    */
       pub_EC_POINT;                    /* Public value           */
CALL CSFPDVK;

handle_GenSec_B = target_key_handle;


/*********************************************************************/
/* Step 3.3 Derive a key using ECDH(HYBRID_NULL) with Alice's Private*/
/* ECC key and Bob's Public ECC key                                  */
/*********************************************************************/
testN = 'DRVGENSECA';
pub_EC_POINT = CSFPGAV(handle_EC_Pub_B,CKA_EC_POINT);
rule_array                = 'EC-DH   ';
attribute_list            = DVK_attr_list_ECDH;
base_key_handle           = handle_EC_Priv_A;
DVK_ParmsList                =,
       CKD_IBM_HYBRID_NULL          ||, /* KDF function code      */
       '00000000'X                  ||, /* Optional data length   */
       '0000000000000000'X          ||, /* Optional data address  */
       D2C(LENGTH(pub_EC_POINT),4)  ||, /* Public value length    */
       pub_EC_POINT;                    /* Public value           */
CALL CSFPDVK;
handle_GenSec_A = target_key_handle;


/*********************************************************************/
/* Step 3.4 Derive key using KYBER(HYBRID_SHA256), then encapsulate  */
/* Bob's Public Kyber key                                            */
/*********************************************************************/
testN = 'DRVSHAREDA';
rule_array                = 'KYBER   ';
attribute_list            = DVK_attr_list_Kyber;
base_key_handle           = handle_Kyb_Pub_B;

DVK_ParmsList                =,
       '00000000'X                  ||, /* version                   */
       CK_IBM_KEM_ENCAPSULATE       ||, /* mode                      */
       CKD_IBM_HYBRID_SHA256_KDF    ||, /* kdf                       */
       CK_FALSE                     ||, /* prepend                   */
       COPIES('00'X,3)              ||, /* reserved                  */
       D2C(0,4)                     ||, /* shared data len           */
       D2C(1600,4)                  ||, /* cipher len (output)       */
       handle_GenSec_A              ||, /* gen secret key handle     */
       COPIES('42'X,1600);              /* buffer for cipher output  */

CALL CSFPDVK;
CALL parse_Kyber_parmslist;
handle_SharedKey_A = target_key_handle;



/*********************************************************************/
/* Step 4.1 Derive key using KYBER(HYBRID_SHA256) using decapsulate  */
/* with Bob's Private Kyber key                                      */
/*********************************************************************/
testN = 'DRVSHAREDB';
rule_array                = 'KYBER   ';
attribute_list            = DVK_attr_list_Kyber;
base_key_handle           = handle_Kyb_Priv_B;
DVK_ParmsList                =,
       '00000000'X                  ||, /* version                   */
       CK_IBM_KEM_DECAPSULATE       ||, /* mode                      */
       CKD_IBM_HYBRID_SHA256_KDF    ||, /* kdf                       */
       CK_FALSE                     ||, /* prepend                   */
       COPIES('00'X,3)              ||, /* reserved                  */
       D2C(0,4)                     ||, /* shared data len           */
       d2c( length(cphr),4  )       ||, /* cipher len (input)        */
       handle_GenSec_B              ||, /* gen secret key handle     */
       cphr                         ;   /* cipher from previous step */
CALL CSFPDVK;
handle_SharedKey_B = target_key_handle;


/*********************************************************************/
/* Encrypt some data with Alice's SharedKey                          */
/*********************************************************************/
testN = 'ENCSHAREDA';
rule_array                = 'AES     ECB     ONLY    ';
key_handle                = handle_SharedKey_A
init_vector               = '';
clear_text                = known_clear_text;
CALL CSFPSKE;
SAY 'ciphertext('||testN||'): '||C2X(cipher_text);
cipher_text_SharedKey_A = cipher_text;

/*********************************************************************/
/* Encrypt some data with Bob's SharedKey                            */
/*********************************************************************/
 testN = 'ENCSHAREDB';
rule_array                = 'AES     ECB     ONLY    ';
key_handle                = handle_SharedKey_B;
init_vector               = '';
clear_text                = known_clear_text;
CALL CSFPSKE;
SAY 'ciphertext('||testN||'): '||C2X(cipher_text);
cipher_text_SharedKey_B = cipher_text;

/*********************************************************************/
/* Verify cipher text is identical                                   */
/*********************************************************************/
IF cipher_text_SharedKey_B = cipher_text_SharedKey_A THEN
  SAY 'TESTCASE SUCCESSFUL'


GETOUT: ;
EXIT;
/*********************************************************************/
/* parse_Kyber_parmslist                                             */
/*********************************************************************/
parse_Kyber_parmslist:
    PARSE VALUE DVK_ParmsList WITH ,
              ver              +4  ,
              mode             +4  ,
              kdf              +4  ,
              pre              +1  ,
              rsvd             +3  ,
              shrdlen          +4  ,
              cphrlen          +4  ,
              gskH             +44 ,
              remaining            ;
    shrdlenD = C2D(shrdlen);
    cphrlenD = C2D(cphrlen);
    PARSE VALUE remaining WITH ,
              shrd             +(shrdlenD) ,
              cphr             +(cphrlenD) ,
              extra                        ;
    verP     = "'"||C2X(ver)||"'X (version "||C2D(ver)||")";
    modeP    = "'"||C2X(mode)||"'X";
    SELECT;
      WHEN mode = CK_IBM_KEM_ENCAPSULATE THEN
        modeP = modeP||" (CK_IBM_KEM_ENCAPSULATE)";
      WHEN mode = CK_IBM_KEM_DECAPSULATE THEN
        modeP = modeP||" (CK_IBM_KEM_DECAPSULATE)";
      OTHERWISE
        modeP = modeP||" (unknown)";
    END;
    kdfP     = "'"||C2X(kdf)||"'X";
    SELECT;
      WHEN kdf = CKD_IBM_HYBRID_SHA1_KDF THEN
        kdfP = kdfP||" (CKD_IBM_HYBRID_SHA1_KDF)";
      WHEN kdf = CKD_IBM_HYBRID_SHA224_KDF THEN
        kdfP = kdfP||" (CKD_IBM_HYBRID_SHA224_KDF)";
      WHEN kdf = CKD_IBM_HYBRID_SHA256_KDF THEN
        kdfP = kdfP||" (CKD_IBM_HYBRID_SHA256_KDF)";
      WHEN kdf = CKD_IBM_HYBRID_SHA384_KDF THEN
        kdfP = kdfP||" (CKD_IBM_HYBRID_SHA384_KDF)";
      WHEN kdf = CKD_IBM_HYBRID_SHA512_KDF THEN
        kdfP = kdfP||" (CKD_IBM_HYBRID_SHA512_KDF)";
      OTHERWISE
        kdfP = kdfP||" (unknown)";
    END;
    preP     = "'"||C2X(pre)||"'X";
    SELECT;
      WHEN pre = CK_FALSE THEN
        preP = preP||"       (don't prepend)";
      WHEN pre = CK_TRUE THEN
        preP = preP||"       (do prepend)";
      OTHERWISE
        preP = preP||"       (unknown)";
    END;
    rsvdP    = "'"||C2X(rsvd)||"'X";
    shrdlenP = "'"||C2X(shrdlen)||"'X ("||shrdlenD||")";
    cphrlenP = "'"||C2X(cphrlen)||"'X ("||cphrlenD||")";
    gskHP    = "'"||gskH||"'";

RETURN;

/* --------------------------------------------------------------- */
/* PKCS #11 Generate Key Pair                                      */
/*                                                                 */
/* Use the PKCS #11 Generate Key Pair callable service to generate */
/* an RSA, DSA, Elliptic Curve, Diffie-Hellman, Dilithium (LI2) or */
/* Kyber key pair.                                                 */
/*                                                                 */
/* See the ICSF Application Programmer's Guide for more details.   */
/* --------------------------------------------------------------- */
CSFPGKP:
return_code               = 'FFFFFFFF'X;
reason_code               = 'FFFFFFFF'X;
token_handle              = my_token;
rule_array_count          = '00000000'X;
rule_array                = '';
/* pub_key_attr_list is set by caller */
pub_key_attr_list_length  = D2C(LENGTH(pub_key_attr_list),4);
pub_key_object_handle     = COPIES(' ',44);
/* prv_key_attr_list is set by caller */
prv_key_attr_list_length  = D2C(LENGTH(prv_key_attr_list),4);
prv_key_object_handle     = COPIES(' ',44);
ADDRESS LINKPGM 'CSFPGKP',
                'return_code'               'reason_code'        ,
                'exit_data_length'          'exit_data'          ,
                'token_handle'                                   ,
                'rule_array_count'          'rule_array'         ,
                'pub_key_attr_list_length'  'pub_key_attr_list'  ,
                'pub_key_object_handle'                          ,
                'prv_key_attr_list_length'  'prv_key_attr_list'  ,
                'prv_key_object_handle'                         ;
IF (return_code \= ExpRC) | (reason_code \= ExpRS) THEN
  DO;
    SAY 'GKP('||testN||'): rc/rs='||C2X(return_code)||'/'||,
                                    C2X(reason_code);
    SIGNAL GETOUT;
  END;
Else
  DO;
    SAY 'GKP('||testN||'): successful';
    SAY '  pub_key_object_handle = "'||pub_key_object_handle||'"';
    SAY '  prv_key_object_handle = "'||prv_key_object_handle||'"';
  END;

RETURN;

/* --------------------------------------------------------------- */
/* PKCS #11 Derive Key                                             */
/*                                                                 */
/* Use the PKCS #11 Derive Key callable service to generate a new  */
/* secret key object from an existing key object.                  */
/*                                                                 */
/* See the ICSF Application Programmer's Guide for more details.   */
/* --------------------------------------------------------------- */
CSFPDVK:
return_code               = 'FFFFFFFF'X;
reason_code               = 'FFFFFFFF'X;
rule_array_count          = D2C(TRUNC((LENGTH(rule_array)+7)/8),4);
/* rule_array (properly padded) is set by caller */
/* attribute_list is set by caller */
attribute_list_length     = D2C(LENGTH(attribute_list),4);
/* base_key_handle is set by caller */
/* DVK_ParmsList is set by caller */
DVK_ParmsList_length         = D2C(LENGTH(DVK_ParmsList),4);
target_key_handle         = COPIES('DD'X,44);
ADDRESS LINKPGM 'CSFPDVK',
                'return_code'               'reason_code'        ,
                'exit_data_length'          'exit_data'          ,
                'rule_array_count'          'rule_array'         ,
                'attribute_list_length'     'attribute_list'     ,
                'base_key_handle'                                ,
                'DVK_ParmsList_length'         'DVK_ParmsList'         ,
                'target_key_handle'                              ;
IF (return_code \= ExpRC) | (reason_code \= ExpRS) THEN
  DO;
    SAY 'DVK('||testN||'): rc/rs='||C2X(return_code)||'/'||,
                                    C2X(reason_code);
    SIGNAL GETOUT;
  END;
Else
  DO;
    SAY 'DVK('||testN||'): successful';
    SAY '  target_key_handle = "'||target_key_handle||'"';
  END;
RETURN;


/* --------------------------------------------------------------- */
/* PKCS #11 Secret Key Encrypt                                     */
/*                                                                 */
/* Use the PKCS #11 Secret Key Encrypt callable service to encipher*/
/* data using a symmetric key.                                     */
/*                                                                 */
/* See the ICSF Application Programmer's Guide for more details.   */
/* --------------------------------------------------------------- */
CSFPSKE:
return_code               = '99999999'X;
reason_code               = '99999999'X;
rule_array_count          = D2C(TRUNC((LENGTH(rule_array)+7)/8),4);
/* rule_array (properly padded) is set by caller */
/* key_handle is set by caller */
init_vector_length        = D2C(LENGTH(init_vector),4);
/* init_vector is set by caller */
chain_data_length         = '00000080'X
chain_data                = COPIES('00'X,C2D(chain_data_length));
clear_text_length         = D2C(LENGTH(clear_text),4);
/* clear_text is set by caller */
clear_text_id             = '00000000'X;
cipher_text_length        = D2C(C2D(clear_text_length)+16,4);
cipher_text               = COPIES('00'X,C2D(cipher_text_length));
cipher_text_id            = '00000000'X;
ADDRESS LINKPGM 'CSFPSKE'                               ,
                'return_code'          'reason_code'    ,
                'exit_data_length'     'exit_data'      ,
                'rule_array_count'     'rule_array'     ,
                'key_handle'                            ,
                'init_vector_length'   'init_vector'    ,
                'chain_data_length'    'chain_data'     ,
                'clear_text_length'    'clear_text'     ,
                'clear_text_id'                         ,
                'cipher_text_length'   'cipher_text'    ,
                'cipher_text_id'                        ;
IF (return_code \= ExpRC) | (reason_code \= ExpRS) THEN
  DO;
    SAY 'SKE('||testN||'): rc/rs='||C2X(return_code)||'/'||,
                                    C2X(reason_code);
    SIGNAL GETOUT;
  END;
Else
  SAY 'SKE('||testN||'): successful';
cipher_text = LEFT(cipher_text,C2D(cipher_text_length));
RETURN;

/* --------------------------------------------------------------- */
/* PKCS #11 Get Attribute Value                                    */
/*                                                                 */
/* Use the PKCS #11 Get Attribute Value callable service (CSFPGAV) */
/* to retrieve the attributes of an object.                        */
/*                                                                 */
/* See the ICSF Application Programmer's Guide for more details.   */
/* --------------------------------------------------------------- */
CSFPGAV:
PARSE ARG RATTR.handle,RATTR.attr;
shortHandle = LEFT(RATTR.handle,41);
return_code      = 'FFFFFFFF'X;
reason_code      = 'FFFFFFFF'X;
rule_array_count = '00000000'X;
handle           = RATTR.handle;
rule_array       = '';
attr_list_length = D2C(32000,4);
attr_list        = COPIES('FF'X,32000);
ADDRESS LINKPGM 'CSFPGAV' ,
                'return_code'      'reason_code'   ,
                'exit_data_length' 'exit_data'     ,
                'handle'                           ,
                'rule_array_count' 'rule_array'    ,
                'attr_list_length' 'attr_list'     ;
IF (return_code \= ExpRC) | (reason_code \= ExpRS) THEN
  DO;
    SAY 'CSFPGAV('||shortHandle||'): rc = '||C2X(return_code)||,
                 ' rs = '||C2X(reason_code);
    SIGNAL GETOUT;
  END;
attr_list = LEFT(attr_list,C2D(attr_list_length));
number_attributes = C2D(LEFT(attr_list,2));
attr_list = SUBSTR(attr_list,3);
DO n = 1 TO number_attributes;
  attr_number  = LEFT(attr_list,4);
  attr_list    = SUBSTR(attr_list,5);
  attr_val_len = C2D(LEFT(attr_list,2));
  attr_list    = SUBSTR(attr_list,3);
  attr_value   = LEFT(attr_list,attr_val_len);
  attr_list    = SUBSTR(attr_list,attr_val_len+1);
  IF (attr_number = RATTR.attr) THEN
    SIGNAL DONE_W_READ_ATTR;
END;
attr_value = 'BADBADBAD';
DONE_W_READ_ATTR: ;
RETURN attr_value;

TCSETUP:

DER_OID_KYBER_1024_R2 = '060B2B0601040102820B050404'X;
secp521r1             = '06052b81040023'x

CKK_IBM_KYBER         = '80010024'X;
CKK_EC                = '00000003'X
CKK_GENERIC_SECRET    = '00000010'X
CKK_AES               = '0000001F'X

CKO_PUBLIC_KEY        = '00000002'X
CKO_PRIVATE_KEY       = '00000003'X
CKO_SECRET_KEY        = '00000004'X

CKA_CLASS             = '00000000'X
CKA_TOKEN             = '00000001'X
CKA_IBM_KYBER_MODE    = '8000000E'X
CKA_LABEL             = '00000003'X
CKA_IBM_SECURE        = '80000006'X
CKA_EC_PARAMS         = '00000180'X
CKA_EC_POINT          = '00000181'X
CKA_VALUE_LEN         = '00000161'X
CKA_KEY_TYPE          = '00000100'X

CKD_IBM_HYBRID_NULL        = '80000001'X;
CKD_IBM_HYBRID_SHA1_KDF    = '80000002'X;
CKD_IBM_HYBRID_SHA224_KDF  = '80000003'X;
CKD_IBM_HYBRID_SHA256_KDF  = '80000004'X;
CKD_IBM_HYBRID_SHA384_KDF  = '80000005'X;
CKD_IBM_HYBRID_SHA512_KDF  = '80000006'X;

CK_IBM_KEM_ENCAPSULATE    = '00000001'X;
CK_IBM_KEM_DECAPSULATE    = '00000002'X;

CK_TRUE                   = '01'x
CK_FALSE                  = '00'x
return

NOVALUE:
SAY "Condition NOVALUE was raised."
SAY CONDITION("D") "variable was not initialized."
SAY sigl||': '||SOURCELINE(sigl)
EXIT; 