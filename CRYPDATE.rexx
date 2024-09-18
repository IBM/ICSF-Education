/* Rexx */

Exp_RC = '00000000'x
Exp_RS = '00000000'x

/*---------------------------------------------------------------------*/
/* Write the Crypto Validty period to a TKDS Object using the Key      */
/* Metadata write service. This sample can be updated for CKDS or PKDS */
/* records by changing the label and rule array.                       */
/*---------------------------------------------------------------------*/

/* Update to the CKDS, PKDS, or TKDS record to be updated. Ensure the
   correct padding is applied. */

Pubkey_label  = left('QSAFE.TEST.TOKEN3               00000003Y',44)
Privkey_label = left('QSAFE.TEST.TOKEN3               00000004Y',44)



/* Rules CKDS , PKDS, and TKDS are supported */
DMW_Rule_Array   = 'TKDS    '
DMW_label_count  = '00000002'x
DMW_Label_List   = Pubkey_label ||  Privkey_label

/* Update the start and end dates in the metadata list below to suit
   your needs.                                                       */
DMW_metadata_list  = ,
                   '000C'x||,       /* block len                     */
                   '0004'x||,       /* Key validity start date tag   */
                   '20240917'||,    /* Start date in YYYYMMDD format */
                   '000C'x||,       /* block len                     */
                   '0005'x||,       /* Key validity end date tag     */
                   '20250917'       /* End date in YYYYMMDD format   */

call CSFKDMW



exit

/*---------------------------------------------------------------------*/
/* Key Data Set Metadata Write (CSFKDMW and CSFKDMW6)

 Use the Key Data Set Metadata Write callable service to add, delete,
 or modify metadata of a set of records in the active CKDS, PKDS, 
 or TKDS.                                                              */
/*---------------------------------------------------------------------*/

CSFKDMW:

DMW_RC                     = 'FFFFFFFF'X
DMW_RS                     = 'FFFFFFFF'X
DMW_Exit_length            = '00000000'x
DMW_Exit_Data              = '';
DMW_Rule_Count             = '00000001'x
DMW_metadata_list_length   = D2C( Length(DMW_metadata_list),4 );
DMW_results_list           = copies('c1'x,8*c2d(DMW_label_count));
DMW_rsv1_length            = '00000000'x
DMW_rsv2_length            = '00000000'x
DMW_rsv2_data              = '';


address linkpgm 'CSFKDMW',
                'DMW_RC'           'DMW_RS',
                'DMW_Exit_Length'  'DMW_Exit_Data',
                'DMW_Rule_Count'   'DMW_Rule_Array',
                'DMW_Label_Count',
                'DMW_Label_List',
                'DMW_metadata_list_length',
                'DMW_metadata_list',
                'DMW_results_list',
                'DMW_Rsv1_Length'  'DMW_Rsv1_data',
                'DMW_Rsv2_Length'  'DMW_Rsv2_data'

 if (DMW_RC = Exp_RC) & (DMW_RS = Exp_RS) Then
     say 'DMW successful : rc =' c2x(DMW_rc) 'rs =' c2x(DMW_rs) ;
 else
   do;
     say 'DMW failed: rc =' c2x(DMW_rc) 'rs =' c2x(DMW_rs) ;
   end;

 if ((DMW_RC = '00000000'x) & (DMW_RS = '00000000'x)) |,
    ((DMW_RC = '00000004'x) & (DMW_RS = '00000D12'x)) Then
  do
     say 'DMW_results_list : '
     do i = 1 to length(DMW_results_list) by 8
       rc_entry = substr(DMW_results_list,i,4)
       rs_entry = substr(DMW_results_list,i+4,4)
       say '     ' c2x(rc_entry) c2x(rs_entry)
     end;


return