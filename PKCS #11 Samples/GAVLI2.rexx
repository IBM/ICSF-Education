/* Rexx */
/*-------------------------------------------------------------------*/
/* Retrieve the attributes of an public Dilithium TKDS object        */
/*-------------------------------------------------------------------*/

/* TKDS Dilithium public key handle name                             */
Pubkey_label  = left('QSAFE.TEST.TOKEN3               00000007Y',44) 

GAV_object_handle = Pubkey_label

Call CSFPGAV

PubKey_Mode       = x2c(ATTRVAL("CKA_IBM_DILITHIUM_MODE",GAV_attrlist))   
PubKey_value      = x2c(ATTRVAL("CKA_VALUE",GAV_attrlist))           
pubkey_mode_len   = D2C( Length( PubKey_Mode ),2);
pubkey_value_len  = D2C( Length( PubKey_value ),2);

say 'PubKey_Mode: ' c2x(PubKey_Mode)
say 'Pubkey_mode_len: ' c2x(pubkey_mode_len)

say 'PubKey_value: '  c2x(PubKey_value)
say 'Pubkey_value_len: ' c2x(pubkey_value_len)




exit
/* --------------------------------------------------------------- */
/* PKCS #11 Get Attribute Value                                    */
/* --------------------------------------------------------------- */
CSFPGAV:
 
GAV_RC          = 'FFFFFFFF'x   
GAV_RS          = 'FFFFFFFF'x   
GAV_exit_length = '00000000'x  
GAV_exit_data   = ''  
GAV_rule_count  = '00000000'x  
GAV_rule_array  = ''    
GAV_attrlist_length = '00002000'x   
GAV_attrlist        = copies( '22'x, 8192 )
 
address linkpgm 'CSFPGAV',         
                'GAV_RC'                'GAV_RS',  
                'GAV_exit_length'       'GAV_exit_data',
                'GAV_object_handle',               
                'GAV_rule_count'        'GAV_rule_array',
                'GAV_attrlist_length'   'GAV_attrlist'
                                                                
  if (GAV_RC = '00000000'x) & (GAV_RS = '00000000'x) Then
    say 'GAV successful : rc =' c2x(GAV_rc) 'rs =' c2x(GAV_rs) ;
else                                                 
  do;                                                
    say 'GAV failed: rc =' c2x(GAV_rc) 'rs =' c2x(GAV_rs) ;                     
  end;
                
GAV_attrlist = substr(GAV_attrlist,1,c2d(GAV_attrlist_length))
 
return;
/* --------------------------------------------------------------- */
/* Returns the value of a specific attribute in a normal PKCS#11   */
/* attribute list.                                                 */
/* --------------------------------------------------------------- */
ATTRVAL:
parse arg attrname, attrs

attrname_hex = value(attrname)
NumAttrs = c2d(substr(attrs,1,2)) /* Parse off how many attrs */
if NumAttrs > 50 then do
   say "Number of attributes in attr list too large:" NumAttrs
   say "Suspect input attribute list is corrupted. Aborting."
   exit
end
ListIndex = 3                   /* Cursor starts just beyond num attrs */
Do k = 1 to NumAttrs
   attr = Substr( attrs, ListIndex, 4 )
   xxx = hex2attr(attr)
   if attrname = xxx then do
      ListIndex = ListIndex + 4
      AttrLength = c2d( Substr( attrs, listIndex, 2 ))
      ListIndex = ListIndex + 2 /* Move past attribute length */
      ATTRVAL = c2x(Substr(attrs,ListIndex,AttrLength))
      return ATTRVAL
   End
   else do /* Skip this attribute */
      ListIndex = ListIndex + 4 /* Skip over attribute name */
      AttrLength = c2d(Substr(attrs,listIndex,2))
      ListIndex = ListIndex + 2 + AttrLength
   end
End /* do k */

return 'ERROR'

/* --------------------------------------------------------------- */
/* Input is hex value pertaining to known PKCS attribute.          */
/* output is char string of that attribute name.                   */
/* --------------------------------------------------------------- */
hex2attr:
parse arg attrhexval

Select
   When attrhexval = '0000010C'x then return "CKA_DERIVE"
   When attrhexval = '00000000'x then return "CKA_CLASS"
   When attrhexval = '00000001'x then return "CKA_TOKEN"
   When attrhexval = '00000002'x then return "CKA_PRIVATE"
   When attrhexval = '00000003'x then return "CKA_LABEL"
   When attrhexval = '00000010'x then return "CKA_APPLICATION"
   When attrhexval = '00000011'x then return "CKA_VALUE"
   When attrhexval = '00000012'x then return "CKA_OBJECT_ID"
   When attrhexval = '00000080'x then return "CKA_CERTIFICATE_TYPE"
   When attrhexval = '00000081'x then return "CKA_ISSUER"
   When attrhexval = '00000082'x then return "CKA_SERIAL_NUMBER"
   When attrhexval = '00000083'x then return "CKA_AC_ISSUER"
   When attrhexval = '00000084'x then return "CKA_OWNER"
   When attrhexval = '00000085'x then return "CKA_ATTR_TYPES"
   When attrhexval = '00000086'x then return "CKA_TRUSTED"
   When attrhexval = '00000087'x then return "CKA_CERTIFICATE_CATEGORY"
   When attrhexval = '00000090'x then return "CKA_CHECK_VALUE"
   When attrhexval = '00000100'x then return "CKA_KEY_TYPE"
   When attrhexval = '00000101'x then return "CKA_SUBJECT"
   When attrhexval = '00000102'x then return "CKA_ID"
   When attrhexval = '00000103'x then return "CKA_SENSITIVE"
   When attrhexval = '00000104'x then return "CKA_ENCRYPT"
   When attrhexval = '00000105'x then return "CKA_DECRYPT"
   When attrhexval = '00000106'x then return "CKA_WRAP"
   When attrhexval = '00000107'x then return "CKA_UNWRAP"
   When attrhexval = '00000108'x then return "CKA_SIGN"
   When attrhexval = '00000109'x then return "CKA_SIGN_RECOVER"
   When attrhexval = '0000010A'x then return "CKA_VERIFY"
   When attrhexval = '0000010B'x then return "CKA_VERIFY_RECOVER"
   When attrhexval = '0000010C'x then return "CKA_DERIVE"
   When attrhexval = '00000110'x then return "CKA_START_DATE"
   When attrhexval = '00000111'x then return "CKA_END_DATE"
   When attrhexval = '00000120'x then return "CKA_MODULUS"
   When attrhexval = '00000121'x then return "CKA_MODULUS_BITS"
   When attrhexval = '00000122'x then return "CKA_PUBLIC_EXPONENT"
   When attrhexval = '00000123'x then return "CKA_PRIVATE_EXPONENT"
   When attrhexval = '00000124'x then return "CKA_PRIME_1"
   When attrhexval = '00000125'x then return "CKA_PRIME_2"
   When attrhexval = '00000126'x then return "CKA_EXPONENT_1"
   When attrhexval = '00000127'x then return "CKA_EXPONENT_2"
   When attrhexval = '00000128'x then return "CKA_COEFFICIENT"
   When attrhexval = '00000130'x then return "CKA_PRIME"
   When attrhexval = '00000131'x then return "CKA_SUBPRIME"
   When attrhexval = '00000132'x then return "CKA_BASE"
   When attrhexval = '00000133'x then return "CKA_PRIME_BITS"
   When attrhexval = '00000134'x then return "CKA_SUBPRIME_BITS"
   When attrhexval = '00000160'x then return "CKA_VALUE_BITS"
   When attrhexval = '00000161'x then return "CKA_VALUE_LEN"
   When attrhexval = '00000162'x then return "CKA_EXTRACTABLE"
   When attrhexval = '00000163'x then return "CKA_LOCAL"
   When attrhexval = '00000164'x then return "CKA_NEVER_EXTRACTABLE"
   When attrhexval = '00000165'x then return "CKA_ALWAYS_SENSITIVE"
   When attrhexval = '00000166'x then return "CKA_KEY_GEN_MECHANISM"
   When attrhexval = '00000170'x then return "CKA_MODIFIABLE"
   When attrhexval = '00000180'x then return "CKA_EC_PARAMS"
   When attrhexval = '00000181'x then return "CKA_EC_POINT"
   When attrhexval = '00000200'x then return "CKA_SECONDARY_AUTH"
   When attrhexval = '00000201'x then return "CKA_AUTH_PIN_FLAGS"
   When attrhexval = '00000300'x then return "CKA_HW_FEATURE_TYPE"
   When attrhexval = '00000301'x then return "CKA_RESET_ON_INIT"
   When attrhexval = '00000302'x then return "CKA_HAS_RESET"
   When attrhexval = '80000000'x then return "CKA_VENDOR_DEFINED"
   When attrhexval = '80000002'x then return "CKA_IBM_DEFAULT"
   When attrhexval = '00000202'x then return "CKA_ALWAYS_AUTHENTICATE"
   When attrhexval = '00000210'x then return "CKA_WRAP_WITH_TRUSTED"
   When attrhexval = '00000211'x then return "CKA_WRAP_TEMPLATE"
   When attrhexval = '00000212'x then return "CKA_UNWRAP_TEMPLATE"
   When attrhexval = '00000400'x then return "CKA_PIXEL_X"
   When attrhexval = '00000401'x then return "CKA_PIXEL_Y"
   When attrhexval = '00000402'x then return "CKA_RESOLUTION"
   When attrhexval = '00000403'x then return "CKA_CHAR_ROWS"
   When attrhexval = '00000404'x then return "CKA_CHAR_COLUMNS"
   When attrhexval = '00000405'x then return "CKA_COLOR"
   When attrhexval = '00000406'x then return "CKA_BITS_PER_PIXEL"
   When attrhexval = '00000480'x then return "CKA_CHAR_SETS"
   When attrhexval = '00000481'x then return "CKA_ENCODING_METHODS"
   When attrhexval = '00000500'x then return "CKA_MECHANISM_TYPE"
   When attrhexval = '00000501'x then return "CKA_REQUIRED_CMS_ATTRIBUTES"
   When attrhexval = '00000502'x then return "CKA_DEFAULT_CMS_ATTRIBUTES"
   When attrhexval = '00000503'x then return "CKA_SUPPORTED_CMS_ATTRIBUTES"
   When attrhexval = '00000600'x then return "CKA_ALLOWED_MECHANISMS"
   When attrhexval = '80000005'x then return "CKA_IBM_FIPS140"
   When attrhexval = '80000006'x then return "CKA_IBM_SECURE"
   When attrhexval = '80010004'x then return "CKA_IBM_ATTRBOUND"
   When attrhexval = '80000007'x then return "CKA_IBM_CARD_COMPLIANCE"
   When attrhexval = '80000008'x then return "CKA_IBM_ALWAYS_SECURE"
   When attrhexval = '80010009'x then return "CKA_IBM_ICSF_HANDLE"
   When attrhexval = '8001000C'x then return "CKA_IBM_PROTKEY_EXTRACTABLE"
   When attrhexval = '8001000D'x then
        return "CKA_IBM_PROTKEY_NEVER_EXTRACTABLE"
   When attrhexval = '80050000'x then return "CKA_IBM_REGIONAL"
   When attrhexval = '8000000A'x then return "CKA_IBM_IV_DATA"
   When attrhexval = '8000000E'x then return "CKA_IBM_KYBER"
   When attrhexval = '80000010'x then return "CKA_IBM_DILITHIUM_MODE"
   Otherwise return "UNKNOWN ATTRIBUTE:" C2X(attrhexval)
End    
 
return;
