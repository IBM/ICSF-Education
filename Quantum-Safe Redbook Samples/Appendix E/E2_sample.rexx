/* rexx */

/*-------------------------------------------------------------------*/
/* CCA ML-KEM key encapsulation                                      */
/*-------------------------------------------------------------------*/
Exp_rc = '00000000'x
Exp_rs = '00000000'x

/* symmetric key skeletons                                           */
AES_CIPHER_SKELETON = ,
'0100003805000000000000000000000000000000000000000000020200000100'x||,
'001A0000000000000002000102C000000003E00000000000'x

/* Randomly generate and encrypt a 32b value and return it in an
   encrypted CCA AES key token                                       */
PKE_rule_array = 'ZERO-PAD' ||,
                 'RANDOM  ' ||,
                 'AES-KB  '

/* AES 16b Initialization Vector (IV) left justified in the buffer   */
PKE_keyvalue       = left('01010101010101010202020202020202'x||,
                          '00000000000000000000000000000000'x,256)

/* AES CIPHER key skeleton used to contain the generated key         */
PKE_sym_key_identifier = AES_CIPHER_SKELETON

/* ML-KEM Public key label                                           */
PKE_public_key_identifier = left('MLKEM.1024.PUB.0001',64)

call CSNDPKE

say 'PKE_keyvalue' c2x(PKE_keyvalue)

/* Return the 32b value in a CCA AES key token                       */
PKD_Rule_Array = 'ZERO-PAD' ||,
                 'AES-KB  '

/* ML-KEM Private key label */
PKD_KeyIdentifier = left('MLKEM.1024.PRV.0001',64)

/* ML-KEM Encrypted value from PKE                                   */
PKD_EncKeyValue_length     = PKE_EncKeyvalue_length
PKD_EncKeyValue            = PKE_EncKeyvalue

/* AES CIPHER key skeleton used to contain the decrypted key         */
PKD_sym_key_identifier     = AES_CIPHER_SKELETON ;

call CSNDPKD

say 'PKD_target_Keyvalue' c2x(PKD_target_Keyvalue) 

exit

/* ---------------------------------------------------------------- */
/* PKA Encrypt                                                      */
/*                                                                  */
/* Generates and encrypts a random 32-byte value                    */
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
PKE_sym_key_identifier_length = d2c(length(PKE_sym_key_identifier),4)
PKE_public_key_identifier_length = d2c(length(PKE_public_key_identifier),4)
PKE_EncKeyvalue_length = d2c(1568,4)
PKE_EncKeyvalue = d2c(0,1568)

ADDRESS LINKPGM 'CSNDPKE' ,
                'PKE_rc' ,
                'PKE_rs' ,
                'exit_data_length' ,
                'exit_data' ,
                'PKE_rule_array_count' ,
                'PKE_rule_array' ,
                'PKE_keyvalue_length' ,
                'PKE_keyvalue' ,
                'PKE_sym_key_identifier_length' ,
                'PKE_sym_key_identifier' ,
                'PKE_public_key_identifier_length' ,
                'PKE_public_key_identifier' ,
                'PKE_EncKeyvalue_length' ,
                'PKE_EncKeyvalue' ;

 IF PKE_rc /= Exp_rc | PKE_rs /= Exp_rs THEN
  SAY 'PKE FAILED rc=' c2x(PKE_rc) 'rs =' c2x(PKE_rs) ;
ELSE
 DO
  PKE_EncKeyvalue = ,
     substr(PKE_EncKeyvalue,1,c2d(PKE_EncKeyvalue_length))
  PKE_keyvalue =,
     substr(PKE_keyvalue,1,c2d(PKE_keyvalue_length))
  SAY 'PKE successful'
 END
SAY
RETURN

/* ---------------------------------------------------------------- */
/* PKA Decrypt                                                      */
/*                                                                  */
/* Decrypts the 32-byte value                                       */  
/*                                                                  */
/* See the ICSF Application Programmer's Guide for more details.    */
/* ---------------------------------------------------------------- */

CSNDPKD:

 PKD_rc                     = 'FFFFFFFF'x ;
 PKD_rs                     = 'FFFFFFFF'x ;
 PKD_Exit_length            = '00000000'x ;
 PKD_Exit_Data              = '' ;
 PKD_Rule_Count             =  d2c(length(PKD_Rule_Array)/8,4)
 PKD_sym_key_id_length      = d2c(length(PKD_sym_key_identifier),4)
 PKD_KeyIdentifier_length   = d2c(length(PKD_KeyIdentifier),4)
 PKD_target_Keyvalue        = copies('00'x,256) ;
 PKD_target_Keyvalue_length = d2c(length(PKD_target_Keyvalue),4)

  address linkpgm 'CSNDPKD'                                ,
                 'PKD_rc'                     'PKD_rs'          ,
                 'PKD_Exit_length'            'PKD_Exit_Data'      ,
                 'PKD_Rule_Count'             'PKD_Rule_Array'     ,
                 'PKD_EncKeyValue_length'     'PKD_EncKeyValue'  ,
                 'PKD_sym_key_id_length'      'PKD_sym_key_identifier' ,
                 'PKD_KeyIdentifier_length'   'PKD_KeyIdentifier'   ,
                 'PKD_target_Keyvalue_length' 'PKD_target_Keyvalue' ;

    PKD_target_keyvalue = ,
     substr(PKD_target_keyvalue,1,c2d(PKD_target_keyvalue_length)) ;


  If PKD_rc = Exp_Rc & PKD_rs = Exp_Rc then
   Do;
    say "PKD successful"
    if PKE_Keyvalue /= PKD_target_Keyvalue then
     do
      say '***** Error PKE_keyvalue <> PKD_target_keyvalue *****'
      say ' PKE_keyvalue         : ' PKE_Keyvalue
      say ' PKD_target_Keyvalue  : ' PKD_target_Keyvalue
     end;
   end;
  Else 
    say 'PKD : failed rc =' c2x(PKD_rc) 'rs =' c2x(PKD_rs)

say
return