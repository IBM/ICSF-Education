/* rexx */

/*-------------------------------------------------------------------*/
/* CCA Hybrid Signature scheme using ECDSA for the primary           */
/* signature and CRYSTALS-Dilithium for the secondary signature      */
/*-------------------------------------------------------------------*/

/* expected results */
ExpRc = '00000000'x ;
ExpRs = '00000000'x ;

/* Message to Sign */
message =  'A9993E364706816ABA3E25717850C26C9CD0D89D'X; 

/*-------------------------------------------------------------------*/
/* Build Dilithium skeleton token with key usage                     */
/*-------------------------------------------------------------------*/
PKB_Rule_Array = 'QSA-PAIR' ||,
                 'U-DIGSIG'

/* CRYSTALS-Dilithium 87 Round 3 KVS */
PKB_KVS = '03'x ||, /* Alg Id */
          '00'x ||, /* clear key format */
          '0807'x ||, /* Alg param */
          '0000'x ||, /* clear key len */
          '0000'x /* Reserved */

call CSNDPKB

/*-------------------------------------------------------------------*/
/* Generate the Dilithium key pair using the skeleton token from PKB */
/*-------------------------------------------------------------------*/
PKG_Rule_Array          = 'MASTER  '
PKG_Skeleton_Key        = PKB_Token;
PKG_Skeleton_Key_length = PKB_Token_length;

call CSNDPKG

/* CRYSTALS-Dilithium 87 Round 3 Private key */
Dilithium_priv_key = PKG_Token

/*-------------------------------------------------------------------*/
/* Extract Dilithium public key from the private key token */
/*-------------------------------------------------------------------*/
PKX_source_key = Dilithium_priv_key

call CSNDPKX

Dilithium_pub_key = PKX_token

/*-------------------------------------------------------------------*/
/* Build ECC skeleton token                                          */
/*-------------------------------------------------------------------*/         
PKB_Rule_Array     = 'ECC-PAIR'  

/* ECC P521 KVS */
PKB_KVS =   '00'X    ||,   /*'00'X Prime */                                     
            '00'X    ||,                                         
            '0209'X  ||,   /* '0209'X 521 (Prime) */                            
            '0000'X  ||,                                           
            '0000'X;  

call CSNDPKB

/*-------------------------------------------------------------------*/
/* Generate the ECC key pair using the skeleton token from PKB       */
/*-------------------------------------------------------------------*/
PKG_Rule_Array          = 'MASTER  '
PKG_Skeleton_Key        = PKB_Token;
PKG_Skeleton_Key_length = PKB_Token_length;

call CSNDPKG

/* ECC P 521 Private key */
ECC_priv_key = PKG_Token

/*-------------------------------------------------------------------*/
/* Extract ECC public key from the private key token                 */
/*-------------------------------------------------------------------*/
PKX_source_key = ECC_priv_key

call CSNDPKX
/* ECC P 521 Public key */
ECC_pub_key = PKX_token

/*-------------------------------------------------------------------*/
/* Call the CSNDDSG service passing the ECC private key              */
/*-------------------------------------------------------------------*/
DSG_Rule_Array = 'ECDSA   ' ||,
                 'MESSAGE ' ||,
                 'SHA-512 '

/* ECC  Private key */
DSG_priv_key = ECC_priv_key
DSG_Sig_Field_Length   = D2C(200,4); 

call CSNDDSG

/* Primary Signature                                                 */
ECC_signature = DSG_sig_field

/*-------------------------------------------------------------------*/
/* Call the CSNDDSG service passing the CRYSTALS-Dilithium private   */
/* key. With a Crypto Express8S CCA Coprocessor, the message to be   */
/* signed can be up to 15000 bytes.                                  */
/*-------------------------------------------------------------------*/
DSG_Rule_Array = 'CRDL-DSA' ||,
                 'MESSAGE ' ||,
                 'CRDLHASH'

/* CRYSTALS-Dilithium 87 Round 3 Private key */
DSG_priv_key = Dilithium_priv_key
DSG_Sig_Field_Length   = '00001388'x ;

call CSNDDSG      

/* Secondary Signature                                               */
Dilithium_signature = DSG_sig_field


/*-------------------------------------------------------------------*/
/* Call the CSNDDSV service passing the ECC public                   */
/* key to verify the primary signature                               */
/*-------------------------------------------------------------------*/
DSV_Sig_Field = ECC_signature
DSV_Rule_Array = 'ECDSA   ' ||,
                 'MESSAGE ' ||,
                 'SHA-512 '

/* ECC P521 Public key */
DSV_pub_key = ECC_pub_key


call CSNDDSV 


/*-------------------------------------------------------------------*/
/* Call the CSNDDSV service passing the CRYSTALS-Dilithium public    */
/* key to verify the secondary signature                             */
/*-------------------------------------------------------------------*/
DSV_Sig_Field = Dilithium_signature
DSV_Rule_Array = 'CRDL-DSA' ||,
                 'MESSAGE ' ||,
                 'CRDLHASH'

/* CRYSTALS-Dilithium 87 Round 3 Public key */
DSV_pub_key = Dilithium_pub_key

call CSNDDSV

exit
/* --------------------------------------------------------------- */
/* Digital Signature Generate                                      */
/*                                                                 */
/* Use the Digital Signature Generate callable service to generate */
/* a digital signature using a PKA private key.                    */
/*                                                                 */
/* See the ICSF Application Programmer's Guide for more details.   */
/* --------------------------------------------------------------- */
CSNDDSG:

DSG_rc                 = 'FFFFFFFF'x ;
DSG_rs                 = 'FFFFFFFF'x ;
DSG_Exit_Length        = '00000000'x ;
DSG_Exit_Data          = '' ;
DSG_data               = message
DSG_Data_length        = D2C( Length(DSG_Data),4 );
DSG_Sig_Bit_Length     = '00000000'x ;
DSG_Sig_Field          = copies('00'x,c2d(DSG_Sig_field_length))
DSG_rule_count         = d2c( length(DSG_rule_array)/8,4 )
DSG_priv_key_length    = d2c( length(DSG_priv_key),4 )


address linkpgm 'CSNDDSG' ,
                'DSG_rc' 'DSG_rs' ,
                'DSG_Exit_Length' 'DSG_Exit_Data' ,
                'DSG_Rule_Count' 'DSG_Rule_Array' ,
                'DSG_priv_key_length' 'DSG_priv_key' ,
                'DSG_data_length' 'DSG_data' ,
                'DSG_sig_field_length' ,
                'DSG_sig_bit_length' ,
                'DSG_sig_field' ;

DSG_sig_field = substr(DSG_sig_field,1,c2d(DSG_sig_field_length))

if (DSG_rc \= ExpRc | DSG_rs \= ExpRs) then
  say 'DSG: failed: rc =' c2x(DSG_rc) 'rs =' c2x(DSG_rs)
else
  say 'DSG successful : rc =' c2x(DSG_rc) 'rs =' c2x(DSG_rs) ;

return;
/* --------------------------------------------------------------- */
/* Digital Signature Verify                                        */
/*                                                                 */
/* Use the Digital Signature Verify callable service to verify a   */
/* digital signature using a PKA public key.                       */
/*                                                                 */
/* See the ICSF Application Programmer's Guide for more details.   */
/* --------------------------------------------------------------- */
CSNDDSV:

DSV_rc               = 'FFFFFFFF'x ;
DSV_rs               = 'FFFFFFFF'x ;
DSV_Exit_Length      = '00000000'x ;
DSV_Exit_Data        = '' ;
DSV_Data             = message
DSV_Data_length      = D2C( Length(DSV_Data),4 );
DSV_Sig_Field_Length = d2c( length(DSV_sig_field),4 )
DSV_rule_count       = d2c( length(DSV_rule_array)/8,4 )
DSV_pub_key_length   = d2c( length(DSV_pub_key),4 )

address linkpgm 'CSNDDSV' ,
                'DSV_rc' 'DSV_rs' ,
                'DSV_Exit_Length' 'DSV_Exit_Data' ,
                'DSV_Rule_Count' 'DSV_Rule_Array' ,
                'DSV_pub_key_length' 'DSV_pub_key' ,
                'DSV_data_length' 'DSV_data' ,
                'DSV_sig_field_length' ,
                'DSV_sig_field' ;

if DSV_rc \= ExpRc | DSV_rs \= ExpRs then
  say 'DSV failed: rc =' c2x(DSV_rc) 'rs =' c2x(DSV_rs)
else
  say 'DSV successful : rc =' c2x(DSV_rc) 'rs =' c2x(DSV_rs) ;

return; 

/*------------------------------------------------------------------*/
/* PKA Key Token Build - used to create PKA key tokens.             */
/*                                                                  */
/* See the ICSF Application Programmer's Guide for more details.    */
/*------------------------------------------------------------------*/
CSNDPKB:

/* initialize parameter list */
PKB_Rc            = 'FFFFFFFF'x ;
PKB_Rs            = 'FFFFFFFF'x ;
Exit_Length       = '00000000'x ;
Exit_Data         = '' ;
PKB_Rule_Count    = d2c( length(PKB_Rule_Array)/8,4 )
PKB_KVS_Length    = d2c(length(PKB_KVS),4) ;
PKB_UAD_Length    = '00000000'x ;
PKB_UAD           = ''
PKB_PrivName_Len  = '00000000'x ;
PKB_PrivName      = ''
Reserved2_Length  = '00000000'x ; Reserved2 = '' ;
Reserved3_Length  = '00000000'x ; Reserved3 = '' ;
Reserved4_Length  = '00000000'x ; Reserved4 = '' ;
Reserved5_Length  = '00000000'x ; Reserved5 = '' ;
PKB_Token_Length  = d2c(8000,4) ;
PKB_Token         = copies('00'x,8000) ;


/* call CSNDPKB */
address linkpgm 'CSNDPKB' ,
                'PKB_Rc' 'PKB_Rs' ,
                'Exit_Length' 'Exit_Data' ,
                'PKB_Rule_Count' 'PKB_Rule_Array' ,
                'PKB_KVS_Length' 'PKB_KVS' ,
                'PKB_PrivName_Len' 'PKB_PrivName' ,
                'PKB_UAD_Length' 'PKB_UAD' ,
                'Reserved2_Length' 'Reserved2' ,
                'Reserved3_Length' 'Reserved3' ,
                'Reserved4_Length' 'Reserved4' ,
                'Reserved5_Length' 'Reserved5' ,
                'PKB_Token_Length' 'PKB_Token' ;

if (PKB_Rc \= ExpRc | PKB_Rs \= ExpRs) then
  say 'PKB failed: rc =' c2x(PKB_Rc) 'rs =' c2x(PKB_Rs) ;
else
  do ;
    say 'PKB sucessful: rc =' c2x(PKB_Rc) 'rs =' c2x(PKB_Rs) ;
    PKB_Token = substr(PKB_Token,1,c2d(PKB_Token_Length)) ;
  end

return
/* --------------------------------------------------------------- */
/* PKA Key Generate - Used to generate PKA key pairs               */
/*                                                                 */
/* See the ICSF Application Programmer's Guide for more details.   */
/* --------------------------------------------------------------- */
CSNDPKG:

PKG_rc                = 'FFFFFFFF'x ;
PKG_rs                = 'FFFFFFFF'x ;
PKG_Exit_length       = '00000000'x ;
PKG_Exit_Data         = '' ;
PKG_Rule_count        = d2c( length(PKG_Rule_Array)/8,4 )
PKG_Token_length      = '00001F40'x ;
PKG_Token             = copies('00'x,c2d(PKG_token_length)) ;
PKG_Regen_data        = ''
PKG_Regen_Data_length = d2c( length(PKG_Regen_data),4 )
PKG_Transport_Key_Id  = ''

address linkpgm 'CSNDPKG' ,
                'PKG_rc' 'PKG_rs' ,
                'PKG_Exit_length' 'PKG_Exit_Data' ,
                'PKG_Rule_Count' 'PKG_Rule_Array' ,
                'PKG_Regen_Data_length' 'PKG_Regen_Data' ,
                'PKG_Skeleton_Key_length' 'PKG_Skeleton_Key' ,
                'PKG_Transport_Key_Id' ,
                'PKG_Token_length' 'PKG_Token' ;


if (PKG_rc \= ExpRc | PKG_rs \= ExpRs) then
  say 'PKG failed: rc =' c2x(PKG_rc) 'rs =' c2x(PKG_rs)
else
  Do;
    say 'PKG successful : rc =' c2x(PKG_rc) 'rs =' c2x(PKG_rs) ;
    PKG_Token = substr(PKG_Token,1,c2d(PKG_Token_length)) ;
  End;

Return

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
PKX_token_length     = d2c(8000,4) ;
PKX_token            = copies('00'x,8000) ;

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

IF PKX_rc /= Exprc | PKX_rs /= Exprs THEN
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
