/* rexx */

/*-------------------------------------------------------------------*/
/* Pure ML-DSA Digital signature generation and verification         */
/*-------------------------------------------------------------------*/
/* expected results */
ExpRc = '00000000'x ;
ExpRs = '00000000'x ;

/* Message to Sign */
message =  'A9993E364706816ABA3E25717850C26C9CD0D89D'X ||,
           'A9993E364706816ABA3E25717850C26C9CD0D89D'X ||,
           'A9993E364706816ABA3E25717850C26C9CD0D89D'X;

/*-------------------------------------------------------------------*/
/* Call the CSNDDSG service passing the Pure ML-DSA private key.     */
/* With a Crypto Express8S CCA Coprocessor, the message to be        */
/* signed can be up to 15000 bytes.                                  */
/*-------------------------------------------------------------------*/
DSG_Rule_Array = 'CRDL-DSA' ||,
                 'MESSAGE ' ||,
                 'CRDLHASH'

/* Pure ('05'x) ML-DSA private key label  */
DSG_priv_key = left('MLDSA87.PURE.PRV.0001',64)
DSG_data = message 

call CSNDDSG

/*-------------------------------------------------------------------*/
/* Call the CSNDDSG service passing the Pure ML-DSA public key.      */
/*-------------------------------------------------------------------*/
DSV_Data = DSG_data
DSV_Sig_Field = DSG_sig_field
DSV_Rule_Array = DSG_Rule_Array

/* Pure ('05'x) ML-DSA public key label  */
DSV_pub_key = left('MLDSA87.PURE.PUB.0001',64)

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
DSG_Data_length        = D2C( Length(DSG_Data),4 );
DSG_Sig_Field_Length   = '00001388'x ;
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