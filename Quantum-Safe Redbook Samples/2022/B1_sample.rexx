/* rexx */
/*-------------------------------------------------------------------*/
/* Generate a secure CCA 256-bit AES CIPHER key                      */
/*-------------------------------------------------------------------*/

/* expected results */
ExpRC = '00000000'x ;
ExpRS = '00000000'x ;

/*-------------------------------------------------------------------*/
/* Build skeleton token with key usage and key management            */
/*-------------------------------------------------------------------*/

KTB2_rule_array = 'INTERNAL' ||,
                  'AES     ' ||,
                  'NO-KEY  ' ||,
                  'CIPHER  ' ||,
                  'ENCRYPT ' ||,
                  'DECRYPT ' ||,
                  'C-XLATE ' ||,
                  'ANY-MODE' ||,
                  'NOEX-SYM' ||,
                  'NOEX-RAW' ||,
                  'NOEXUASY' ||,
                  'NOEXAASY' ||,
                  'NOEX-DES' ||,
                  'NOEX-AES' ||,
                  'NOEX-RSA' ||,
                  'XPRTCPAC'

call CSNBKTB2

/*-------------------------------------------------------------------*/
/* Generate the AES key using the skeleton token from KTB2           */
/*-------------------------------------------------------------------*/
KGN2_Rule_Array = 'AES     ' ||,
                  'OP      '
KGN2_clear_key_Bit_Len = '00000100'x /* 256-bit */
KGN2_key_Type_1 = 'TOKEN   '
KGN2_key_Type_2 = ''
KGN2_gen_key_1_Len = '000002D5'x
KGN2_gen_key_1 = left(KTB2_target_key_token,c2d(KGN2_gen_key_1_Len))

call CSNBKGN2

exit

/* --------------------------------------------------------------- */
/* CSNBKTB2 - Key Token Build2                                     */
/*                                                                 */
/* Builds a variable-length AES skeleton token.                    */
/*                                                                 */
/* See the ICSF Application Programmer's Guide for more details.   */
/* --------------------------------------------------------------- */
CSNBKTB2:

KTB2_rc                 = 'ffffffff'x ;
KTB2_rs                 = 'ffffffff'x ;
KTB2_exit_Length        = '00000000'x ;
KTB2_exit_Data          = '' ;
KTB2_key_name_len       = '00000000'x ;
KTB2_key_name           = '';
KTB2_user_data_Len      = '00000000'x ;
KTB2_user_data          = '';
KTB2_token_data_Len     = '00000000'x ;
KTB2_token_data         = '';
KTB2_clear_key          = '';
KTB2_service_data       = '';
KTB2_service_data_Len   = D2C(length(KTB2_service_data),4) ;
KTB2_target_key_token_Len = d2c(725,4) ;
KTB2_target_key_token   = copies('00'x,c2d(KTB2_target_key_token_Len));
KTB2_clear_key_bit_Len  = '00000000'x;
KTB2_Rule_count         = D2C(length(KTB2_rule_array)/8,4);

address linkpgm 'CSNBKTB2' ,
                'KTB2_rc'          'KTB2_rs' ,
                'KTB2_exit_Length' 'KTB2_exit_Data' ,
                'KTB2_rule_count'  'KTB2_rule_array' ,
                'KTB2_clear_key_bit_Len' ,
                'KTB2_clear_key' ,
                'KTB2_key_name_Len' 'KTB2_key_name' ,
                'KTB2_user_data_Len' 'KTB2_user_data' ,
                'KTB2_token_data_Len' 'KTB2_token_data' ,
                'KTB2_service_data_Len' 'KTB2_service_data' ,
                'KTB2_target_key_token_Len' 'KTB2_target_key_token' ;

KTB2_target_key_token = ,
substr(KTB2_target_key_token,1,c2d(KTB2_target_key_token_len))

If (KTB2_RC <> ExpRC) | (KTB2_RS <> ExpRS) then
  do;
   say 'KTB2 failed : rc =' c2x(KTB2_RC) 'rs =' c2x(KTB2_RS)
  end;
else
  say 'KTB2 successful : rc =' c2x(KTB2_RC) 'rs =' c2x(KTB2_RS)

return
/* --------------------------------------------------------------- */
/* CSNBKGN - Key Generate                                          */
/*                                                                 */
/* Generates either one or two DES or AES keys encrypted under a   */
/* master key (internal form) or KEK (external form).              */
/*                                                                 */
/* See the ICSF Application Programmer's Guide for more details.   */
/* --------------------------------------------------------------- */
CSNBKGN2:

KGN2_rc                  = 'ffffffff'x ;
KGN2_rs                  = 'ffffffff'x ;
KGN2_Exit_Length         = '00000000'x ;
KGN2_Exit_Data           = '' ;
KGN2_Rule_count          = D2C(length(KGN2_rule_array)/8,4)
KGN2_key_Name_1_Len      = '00000000'x ;
KGN2_key_Name_1          = '';
KGN2_key_Name_2_Len      = '00000000'x ;
KGN2_key_Name_2          = '';
KGN2_user_data_1_Len     = '00000000'x ;
KGN2_user_data_1         = '';
KGN2_user_data_2_Len     = '00000000'x ;
KGN2_user_data_2         = '';
KGN2_KEK_1_Len           = '00000000'x ;
KGN2_KEK_1               = '';
KGN2_KEK_2_Len           = '00000000'x;
KGN2_KEK_2               = '';
KGN2_gen_key_2_Len       = '00000000'x;
KGN2_gen_key_2           = '';

address linkpgm 'CSNBKGN2' ,
                'KGN2_rc' 'KGN2_rs' ,
                'KGN2_Exit_Length' 'KGN2_Exit_Data' ,
                'KGN2_Rule_Count' 'KGN2_Rule_Array' ,
                'KGN2_clear_key_Bit_Len' ,
                'KGN2_key_Type_1' 'KGN2_key_Type_2' ,
                'KGN2_key_Name_1_Len' 'KGN2_key_Name_1' ,
                'KGN2_key_Name_2_Len' 'KGN2_key_Name_2' ,
                'KGN2_user_data_1_Len' 'KGN2_user_data_1' ,
                'KGN2_user_data_2_Len' 'KGN2_user_data_2' ,
                'KGN2_KEK_1_Len' 'KGN2_KEK_1' ,
                'KGN2_KEK_2_Len' 'KGN2_KEK_2' ,
                'KGN2_gen_key_1_Len' 'KGN2_gen_key_1' ,
                'KGN2_gen_key_2_Len' 'KGN2_gen_key_2' ;
If (KGN2_RC <> ExpRC) | (KGN2_RS <> ExpRS) then
  do;
    say 'KGN2 failed: rc =' c2x(KGN2_RC) 'rs =' c2x(KGN2_RS)
  end;
else
  say 'KGN2 successful: rc =' c2x(KGN2_RC) 'rs =' c2x(KGN2_RS)

KGN2_gen_key_1 = substr(KGN2_gen_key_1,1,c2d(KGN2_gen_key_1_len))
KGN2_gen_key_2 = substr(KGN2_gen_key_2,1,c2d(KGN2_gen_key_2_len))

Return
 