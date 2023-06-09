/* Rexx */

/*-------------------------------------------------------------------*/
/* Translate existing ciphertext to an AES 256-bit key               */
/*-------------------------------------------------------------------*/

 /* expected results */
 ExpRc = '00000000'x
 ExpRs = '00000000'x

 /*------------------------------------------------------------------*/
 /* Call CSNBCTT2 to translate the exisiting ciphertext to AES       */
 /*------------------------------------------------------------------*/
 CTT2_Rule_Count     = '00000004'x
 CTT2_rule_array     = 'I-CBC   '||'O-CBC   '||'IKEY-DES'||'OKEY-AES';
 CTT2_cipher_text_in = 'E7861BBEEA363B3C40168B3174C15D31'x ;

 /* Change these key labels to the correct key labels */
 CTT2_key_ID_in   = left('DATAENC#CTT2#DES#CIPHER#1',64)
 CTT2_key_ID_out  = left('DATAENC#CTT2#AES#CIPHER',64) ;

 Call CSNBCTT2

 exit
/*-------------------------------------------------------------------*/
/* CipherText Translate2                                             */
/*                                                                   */
/* This callable service deciphers encrypted data (ciphertext) under */
/* one cipher text translation key and reenciphers it under another  */
/* cipher text translation key without having the data appear in the */
/* clear outside the cryptographic coprocessor.                      */
/*                                                                   */
/* See the ICSF Application Programmer's Guide for more details.     */
/*-------------------------------------------------------------------*/
CSNBCTT2:

  CTT2_rc                   = 'FFFFFFFF'x ;
  CTT2_rs                   = 'FFFFFFFF'x ;
  CTT2_Exit_Len             = '00000000'x ;
  CTT2_Exit_Data            = '' ;
  CTT2_IV_in_len            = '00000008'X
  CTT2_IV_in                = '0000000000000000'X
  CTT2_cipher_text_in_len   = d2c(length(CTT2_cipher_text_in),4)
  CTT2_chaining_vector_len  = '00000080'X
  CTT2_chaining_vector      = copies('00'x,128)
  CTT2_IV_out_len           = '00000010'X
  CTT2_IV_out               = '0000000000000000'X
  CTT2_rsv1_len             = '00000000'x
  CTT2_rsv1                 = ''
  CTT2_rsv2_len             = '00000000'x
  CTT2_rsv2                 = ''
  CTT2_key_ID_in_len        = '00000040'x
  CTT2_key_ID_out_len       = '00000040'x
  CTT2_cipher_text_out_len  = d2c(length(CTT2_cipher_text_in),4)
  CTT2_cipher_text_out      = copies('00'x,c2d(CTT2_cipher_text_out_len))

  address linkpgm 'CSNBCTT2'                                      ,
                  'CTT2_rc'                  'CTT2_rs'            ,
                  'CTT2_Exit_Len'            'CTT2_Exit_Data'     ,
                  'CTT2_Rule_Count'          'CTT2_Rule_array'    ,
                  'CTT2_key_ID_in_len'       'CTT2_key_ID_in'     ,
                  'CTT2_IV_in_len'           'CTT2_IV_in'         ,
                  'CTT2_cipher_text_in_len'  'CTT2_cipher_text_in',
                  'CTT2_chaining_vector_len' 'CTT2_chaining_vector',
                  'CTT2_key_ID_out_len'      'CTT2_key_ID_out'     ,
                  'CTT2_IV_out_len'          'CTT2_IV_out'         ,
                  'CTT2_cipher_text_out_len' 'CTT2_cipher_text_out',
                  'CTT2_rsv1_len'            'CTT2_rsv1'           ,
                  'CTT2_rsv2_len'            'CTT2_rsv2'           ;

  if (CTT2_rc \= ExpRc | CTT2_rs \= ExpRs) then
   say 'CTT2 failed: rc=' c2x(CTT2_rc) 'rs =' c2x(CTT2_rs) ;
  else
   say 'CTT2 successful: rc=' c2x(CTT2_rc) 'rs =' c2x(CTT2_rs) ;

 return;
 