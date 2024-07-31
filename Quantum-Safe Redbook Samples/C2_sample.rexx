/* rexx */

/*-------------------------------------------------------------------*/
/* Translate existing ciphertext to an AES 256-bit key               */
/*-------------------------------------------------------------------*/

 /* expected results */
 ExpRC = '00000000'x ;
 ExpRS = '00000000'x ;

 SKR_Rule_Array = 'D-CBCPAD' || 'E-CBCPAD'

 /*-------------------------------------------------------------------*/
 /* Pass existing Ciphertext and set IV according to the decryption   */
 /* key. For DES keys, IV length is 8.                                */
 /*-------------------------------------------------------------------*/
 SKR_dec_iv_length     = '00000008'x;
 SKR_dec_iv            = copies('00'x,c2d(SKR_dec_iv_length) )
 SKR_dec_text   =,
 '3AE0F4D65E911F061FED6FEB0CB84D6996A5623CADED94AEA3B8E2923F04E927'x ||,
 'DADFD96CCDDB5497442F6A75C82041AFE418D930AF4DE8B732A4D86C1D3F60EC'x ||,
 '530BB9336A042B2A398FE650B8E38D2451D2427B904ED7B1'x
 SKR_dec_text_length  = d2c(length(SKR_dec_text),4)

 /*-------------------------------------------------------------------*/
 /* Set encryption IV length to 16 for AES                            */
 /*-------------------------------------------------------------------*/
 SKR_enc_iv_length = '00000010'x
 SKR_enc_iv = copies('00'x,c2d(SKR_enc_iv_length))

 /* Secure DES3 handle */
 SKR_dec_handle = 'QSAFE.TEST.TOKEN                00000001Y'
 /* Secure AES 256 handle */
 SKR_enc_handle = 'QSAFE.TEST.TOKEN                00000002Y'

 call CSFPSKR

 exit
/* --------------------------------------------------------------- */
/* PKCS #11 Secret Key Reencrypt                                   */
/*                                                                 */
/* Use the PKCS #11 Secret Key Reencrypt callable service to       */
/* decrypt data and then reencrypt the data using secure secret    */
/* keys.                                                           */
/*                                                                 */
/* See the ICSF Application Programmer's Guide for more details.   */
/* --------------------------------------------------------------- */
CSFPSKR:
 SKR_rc            = 'FFFFFFFF'x ;
 SKR_rs            = 'FFFFFFFF'x ;
 SKR_Exit_Length   = '00000000'x;
 SKR_Exit_Data     = '';
 SKR_Rule_Count    = '00000002'x;
 SKR_chain_data_length = '00000000'x
 SKR_chain_data        = '';
 SKR_dec_text_id       = '00000000'x;
 SKR_enc_text_length   = D2C(1000,4);
 SKR_enc_text          = COPIES('00'x,C2D(SKR_enc_text_length,4));
 SKR_enc_text_id       = '00000000'x;

  address linkpgm 'CSFPSKR'                               ,
                 'SKR_rc'                'SKR_rs'        ,
                 'SKR_Exit_Length'       'SKR_Exit_Data' ,
                 'SKR_Rule_Count'        'SKR_Rule_Array',
                 'SKR_dec_handle'        'SKR_enc_handle',
                 'SKR_dec_iv_length'     'SKR_dec_iv'    ,
                 'SKR_enc_iv_length'     'SKR_enc_iv'    ,
                 'SKR_chain_data_length' 'SKR_chain_data',
                 'SKR_dec_text_length'   'SKR_dec_text'  ,
                 'SKR_dec_text_id'                       ,
                 'SKR_enc_text_length'   'SKR_enc_text'  ,
                 'SKR_enc_text_id'                       ;

 if SKR_rc <> ExpRC | SKR_rs <> ExpRS then
   say 'SKR failed: rc =' c2x(SKR_rc) 'rs =' c2x(SKR_rs)
 else
   say 'SKR successful rc =' c2x(SKR_rc) 'rs =' c2x(SKR_rs)
return;

EXIT; 