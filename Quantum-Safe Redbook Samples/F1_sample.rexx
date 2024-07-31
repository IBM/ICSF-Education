 /* Rexx */

/*-------------------------------------------------------------------*/
/* Generate hash using CCA One-Way Hash service                      */
/*-------------------------------------------------------------------*/

 /* expected results */
 ExpRc = '00000000'x
 ExpRs = '00000000'x


 BOWH_Rule_Array   = 'SHA-512 ' || 'ONLY    ' ;
 BOWH_Text         = '0123456789ABCDEF';
 BOWH_Hash         = copies('00'x, 64);
 BOWH_Chain_Vector = copies('00'x,128);

 call CSNBOWH

 say 'BOWH Hash: ' c2x(BOWH_Hash)

 Exit

/* --------------------------------------------------------------- */
/* One-Way Hash Generate                                           */
/*                                                                 */
/* Used to generate a one-way hash                                 */
/*                                                                 */
/* See the ICSF Application Programmer's Guide for more details.   */
/* --------------------------------------------------------------- */

CSNBOWH:

 /* initialize parameter list */
 BOWH_rc                  = 'FFFFFFFF'x ;
 BOWH_rs                  = 'FFFFFFFF'x ;
 BOWH_Exit_Length         = '00000000'x ;
 BOWH_Exit_Data           = '00000000'x ;
 BOWH_Rule_Count          = d2c(length(BOWH_Rule_Array)/8,4);
 BOWH_Text_Length         = d2c(length(BOWH_Text),4);
 BOWH_Chain_Vector_Length = d2c(length(BOWH_Chain_Vector),4);
 BOWH_Hash_Length         = d2c(Length(BOWH_Hash),4);

 /* call CSNBOWH */
 address linkpgm 'CSNBOWH' ,
                 'BOWH_rc'                  'BOWH_rs'           ,
                 'BOWH_Exit_Data_Length'    'BOWH_Exit_Data'    ,
                 'BOWH_Rule_Count'          'BOWH_Rule_Array'   ,
                 'BOWH_Text_Length'         'BOWH_Text'         ,
                 'BOWH_Chain_Vector_Length' 'BOWH_Chain_Vector' ,
                 'BOWH_Hash_Length'         'BOWH_Hash'         ;

 if (BOWH_rc \= ExpRc | BOWH_rs \= ExpRs) then
  say 'BOWH failed: rc =' c2x(BOWH_rc) 'rs =' c2x(BOWH_rs) ;
 else
  say 'BOWH successful: rc =' c2x(BOWH_rc) 'rs =' c2x(BOWH_rs) ;

return 