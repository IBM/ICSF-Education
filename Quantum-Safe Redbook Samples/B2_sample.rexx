/*rexx*/

/*-------------------------------------------------------------------*/
/* Generate a secure 256-bit PKCS #11 AES key                        */
/*-------------------------------------------------------------------*/
Call TCSetup

/* expected results */
ExpRC = '00000000'x ;
ExpRS = '00000000'x ;

/*-------------------------------------------------------------------*/
/* Generate the AES key using the attribute list                     */
/*-------------------------------------------------------------------*/
GSK_Handle = Left('QSAFE.TEST.TOKEN',44) ;

GSK_AttrList = '0007'x ||, /* number of attributes */
        CKA_CLASS      ||'0004'x || CKO_SECRET_KEY ||,
        CKA_KEY_TYPE   ||'0004'x || CKK_AES        ||,
        CKA_VALUE_LEN  ||'0004'x || '00000020'x    ||, /* AES 256-bit */
        CKA_TOKEN      ||'0001'x || CK_TRUE        ||,
        CKA_IBM_SECURE ||'0001'x || CK_TRUE        ||,
        CKA_ENCRYPT    ||'0001'x || CK_TRUE        ||,
        CKA_DECRYPT    ||'0001'x || CK_TRUE

Call CSFPGSK;

exit
/* --------------------------------------------------------------- */
/* PKCS #11 Generate Secret Key                                    */
/* Use the generate secret key callable service to generate a      */
/* secret key or set of domain parameters.                         */
/*                                                                 */
/* See the ICSF Application Programmer's Guide for more details.   */
/* --------------------------------------------------------------- */
CSFPGSK:

GSK_RC              = 'FFFFFFFF'x ;
GSK_RS              = 'FFFFFFFF'x ;
GSK_Exit_Length     = '00000000'x ;
GSK_Exit_Data       = '' ;
GSK_Rule_Count      = '00000001'x;
GSK_Rule_Array      = 'KEY ';
GSK_Parms_List      = ''
GSK_Parms_List_Length = '00000000'x
GSK_AttrListLength    = D2C( Length( GSK_AttrList ),4);


/* call GSK */
address linkpgm 'CSFPGSK' ,
                'GSK_RC' 'GSK_RS' ,
                'GSK_Exit_Length' 'GSK_Exit_Data' ,
                'GSK_Handle' ,
                'GSK_Rule_Count' 'GSK_Rule_Array' ,
                'GSK_AttrListLength' 'GSK_AttrList' ,
                'GSK_Parms_List_Length' 'GSK_Parms_List' ;

If (GSK_RC <> ExpRC) | (GSK_RS <> ExpRS) then
  say 'GSK failed: rc =' c2x(GSK_rc) 'rs =' c2x(GSK_rs) ;
else
  say 'GSK successful : rc =' c2x(GSK_rc) 'rs =' c2x(GSK_rs) ;

return
/* --------------------------------------------------------------- */
/*                                                                 */
/* --------------------------------------------------------------- */
TCSetup:

CKK_AES           = '0000001F'X
CKO_SECRET_KEY    = '00000004'X
CKA_CLASS         = '00000000'X
CKA_TOKEN         = '00000001'X
CKA_IBM_SECURE    = '80000006'X
CKA_KEY_TYPE      = '00000100'X
CKA_ENCRYPT       = '00000104'X;
CKA_DECRYPT       = '00000105'X;
CKA_VALUE_LEN     = '00000161'X
CK_TRUE           = '01'x
CK_FALSE          = '00'x

Return

EXIT; 