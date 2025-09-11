/* Rexx */

/*-------------------------------------------------------------------*/
/* Generate a secure ML-KEM CCA key pair                             */
/*-------------------------------------------------------------------*/

 /* expected results */
 ExpRc = '00000000'x
 ExpRs = '00000000'x

/*-------------------------------------------------------------------*/
/* Build skeleton token with key usage                               */
/*-------------------------------------------------------------------*/
 PKB_Rule_Count   = '00000003'x ;
 PKB_Rule_Array   = 'QSA-PAIR' ||,
                    'U-KEYENC' ||,
                    'U-DATENC'

 /* ML-KEM-1024 KVS */
 PKB_KVS    = '06'x   ||, /* Alg Id */
              '00'x   ||, /* clear key format */
              '1024'x ||, /* Alg param */
              '0000'x ||, /* clear key len */
              '0000'x     /* Reserved */

 call CSNDPKB

/*-------------------------------------------------------------------*/
/* Generate the ML-KEM key pair using the skeleton token from PKB    */
/*-------------------------------------------------------------------*/
 PKG_Rule_Array = 'MASTER  '
 PKG_Skeleton_Key        = PKB_Token;
 PKG_Skeleton_Key_length = PKB_Token_length;

 call CSNDPKG

 Exit
/*------------------------------------------------------------------*/
/* PKA Key Token Build - used to create PKA key tokens.             */
/*                                                                  */
/* See the ICSF Application Programmer's Guide for more details.    */
/*------------------------------------------------------------------*/
CSNDPKB:

/* initialize parameter list */
PKB_Rc           = 'FFFFFFFF'x ;
PKB_Rs           = 'FFFFFFFF'x ;
Exit_Length      = '00000000'x ;
Exit_Data        = '' ;
PKB_KVS_Length   = d2c(length(PKB_KVS),4) ;
PKB_UAD_Length   = '00000000'x ;
PKB_UAD          = ''
PKB_PrivName_Len = '00000000'x ;
PKB_PrivName     = ''
Reserved2_Length = '00000000'x ; Reserved2 = '' ;
Reserved3_Length = '00000000'x ; Reserved3 = '' ;
Reserved4_Length = '00000000'x ; Reserved4 = '' ;
Reserved5_Length = '00000000'x ; Reserved5 = '' ;
PKB_Token_Length = d2c(8000,4) ;
PKB_Token        = copies('00'x,8000) ;

/* call CSNDPKB */
address linkpgm 'CSNDPKB'                           ,
                'PKB_Rc'           'PKB_Rs'         ,
                'Exit_Length'      'Exit_Data'      ,
                'PKB_Rule_Count'   'PKB_Rule_Array' ,
                'PKB_KVS_Length'   'PKB_KVS'        ,
                'PKB_PrivName_Len' 'PKB_PrivName'   ,
                'PKB_UAD_Length'   'PKB_UAD'        ,
                'Reserved2_Length' 'Reserved2'      ,
                'Reserved3_Length' 'Reserved3'      ,
                'Reserved4_Length' 'Reserved4'      ,
                'Reserved5_Length' 'Reserved5'      ,
                'PKB_Token_Length' 'PKB_Token'      ;

if (PKB_Rc \= ExpRc | PKB_Rs \= ExpRs) then
  say 'PKB failed: rc =' c2x(PKB_Rc) 'rs =' c2x(PKB_Rs) ;
else
 do ;
  say 'PKB successful: rc =' c2x(PKB_Rc) 'rs =' c2x(PKB_Rs) ;
  PKB_Token = substr(PKB_Token,1,c2d(PKB_Token_Length)) ;
 end

 return

/* --------------------------------------------------------------- */
/* PKA Key Generate  - Used to generate PKA key pairs.             */
/*                                                                 */
/* See the ICSF Application Programmer's Guide for more details.   */
/* --------------------------------------------------------------- */
CSNDPKG:

 /* initialize parameter list */
 PKG_rc           = 'FFFFFFFF'x ;
 PKG_rs           = 'FFFFFFFF'x ;
 PKG_Exit_length  = '00000000'x ;
 PKG_Exit_Data    = '' ;
 PKG_Rule_count   = d2c( length(PKG_Rule_Array)/8,4 )
 PKG_Token_length = '00001F40'x ;
 PKG_Token        = copies('00'x,c2d(PKG_token_length)) ;
 PKG_Regen_data   = ''
 PKG_Regen_Data_length = d2c( length(PKG_Regen_data),4 )
 PKG_Transport_Key_Id  = ''

 /* call CSNDPKG */
 address linkpgm 'CSNDPKG' ,
                 'PKG_rc'                  'PKG_rs'           ,
                 'PKG_Exit_length'         'PKG_Exit_Data'    ,
                 'PKG_Rule_Count'          'PKG_Rule_Array'   ,
                 'PKG_Regen_Data_length'   'PKG_Regen_Data'   ,
                 'PKG_Skeleton_Key_length' 'PKG_Skeleton_Key' ,
                 'PKG_Transport_Key_Id'                       ,
                 'PKG_Token_length'        'PKG_Token'        ;

 if (PKG_rc \= ExpRc | PKG_rs \= ExpRs) then
  say 'PKG failed: rc =' c2x(PKG_rc) 'rs =' c2x(PKG_rs)
 else
  Do;
   say 'PKG  successful : rc =' c2x(PKG_rc) 'rs =' c2x(PKG_rs) ;
   PKG_Token = substr(PKG_Token,1,c2d(PKG_Token_length)) ;
  End;

return