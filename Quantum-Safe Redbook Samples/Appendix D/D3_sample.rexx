/* rexx */

/*------------------------------------------------------------------*/
/* ML-DSA Digital signature generation and verification             */
/*------------------------------------------------------------------*/

 /* expected results */
 ExpRC = '00000000'x ;
 ExpRS = '00000000'x ;

/*------------------------------------------------------------------*/
/* Call the CSFPPKS service passing the ML-DSA private key handle   */
/* to generate the digital signature.                               */
/*------------------------------------------------------------------*/
 PKS_Rule_Array          = 'ML-DSA  '
 PKS_Key_Handle          = 'QSAFE.TEST.TOKEN                00000003Y'
 PKS_Cipher_Value        = Copies('A',128)
 PKS_Cipher_Value_Length = D2C( Length(PKS_Cipher_Value),4 );
 PKS_Clear_Value_length  = D2C(4596,4);
 PKS_Clear_Value         = Copies('00'x, C2D(PKS_Clear_Value_length) )

 Call CSFPPKS

/*------------------------------------------------------------------*/
/* Call the CSFPPKV service passing the ML-DSA public key handle to */
/* verify the digital signature.                                    */ 
/*------------------------------------------------------------------*/
 PKV_Key_Handle          = 'QSAFE.TEST.TOKEN                00000002Y'

 Call CSFPPKV

 exit
/* --------------------------------------------------------------- */
/* PKCS #11 Private Key Sign                                       */
/*                                                                 */
/* Used to sign data using an ECC, RSA, DSA, or ML-DSA private     */
/* key.                                                            */
/* --------------------------------------------------------------- */
CSFPPKS:

 PKS_RC              = 'FFFFFFFF'x ;
 PKS_RS              = 'FFFFFFFF'x ;
 PKS_Exit_Length     = '00000000'x ;
 PKS_Exit_Data       = '' ;

 PKS_Rule_Count = d2c( length(PKS_Rule_Array)/8,4 )


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
/* ML-DSA public key.                                              */
/* --------------------------------------------------------------- */
CSFPPKV:

 PKV_RC              = 'FFFFFFFF'x ;
 PKV_RS              = 'FFFFFFFF'x ;
 PKV_Exit_Length     = '00000000'x ;
 PKV_Exit_Data       = '';
 PKV_Cipher_Value_length = PKS_Cipher_Value_length
 PKV_Cipher_Value        = PKS_Cipher_Value
 PKV_Clear_Value         = PKS_Clear_Value
 PKV_Clear_Value_length  = PKS_Clear_Value_length
 PKV_Rule_Array          = PKS_Rule_Array
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