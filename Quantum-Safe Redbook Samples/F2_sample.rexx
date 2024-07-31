/* Rexx */

/*-------------------------------------------------------------------*/
/* Generate hash using PKCS #11 One-Way Hash service                 */
/*-------------------------------------------------------------------*/

 /* expected results */
 ExpRc = '00000000'x
 ExpRs = '00000000'x


 /* Call PKCS#11 One-Way Hash with generated token */
 POWH_Rule_Array   = 'SHA-512 ' || 'ONLY    ' ;
 POWH_Text         = '0123456789ABCDEF';
 POWH_Hash         = copies('00'x, 64);
 POWH_Chain_Vector = copies('00'x,128);
 POWH_Handle       = Left('QSAFE.TEST.TOKEN',44)

 call CSNPOWH

 say 'POWH Hash: ' c2x(POWH_Hash)


 Exit
/* --------------------------------------------------------------- */
/* PKCS #11 One-Way Hash, Sign, or Verify                          */
/*                                                                 */
/* Use the PKCS #11 One-Way Hash, Sign, or Verify callable service */
/* to generate a one-way hash on specified text, sign specified    */
/* text, or verify a signature on specified text.                  */
/*                                                                 */
/* See the ICSF Application Programmer's Guide for more details.   */
/* --------------------------------------------------------------- */

CSNPOWH:

 /* initialize parameter list */
 POWH_RC                  = 'FFFFFFFF'x ;
 POWH_RS                  = 'FFFFFFFF'x ;
 POWH_Exit_Length         = '00000000'x ;
 POWH_Exit_Data           = '' ;
 POWH_Rule_Count          = d2c(length(POWH_Rule_Array)/8,4);
 POWH_Text_Length         = d2c(length(POWH_Text),4);
 POWH_Text_id             = '00000000'x ;
 POWH_Chain_Vector_Length = d2c(length(POWH_Chain_Vector),4);
 POWH_Hash_Length         = D2C(Length(POWH_Hash),4);

 /* call CSNPOWH */
 address linkpgm 'CSFPOWH' ,
                 'POWH_RC'                     'POWH_RS'           ,
                 'POWH_Exit_Length'            'POWH_Exit_Data'    ,
                 'POWH_Rule_Count'             'POWH_Rule_Array'   ,
                 'POWH_Text_Length'            'POWH_Text'         ,
                 'POWH_Text_id'                                    ,
                 'POWH_Chain_Vector_Length'    'POWH_Chain_Vector' ,
                 'POWH_Handle'                                     ,
                 'POWH_Hash_Length'            'POWH_Hash'         ;

 if (POWH_rc \= ExpRc | POWH_rs \= ExpRs) then
  say 'POWH failed: rc =' c2x(POWH_rc) 'rs =' c2x(POWH_rs) ;
 else
  say 'POWH successful: rc =' c2x(POWH_rc) 'rs =' c2x(POWH_rs) ;

 return 