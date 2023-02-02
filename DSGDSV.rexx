/* REXX */                                                                      
SIGNAL ON NOVALUE;                                                              
/*********************************************************************/         
/*    Licensed Materials - Property of IBM.                          */         
/*    5650-ZOS                                                       */         
/*    COPYRIGHT IBM CORP. 2023                                       */         
/*                                                                   */         
/* This REXX exec will:                                              */         
/* 1. Call CSNDPKB/CSNDPKG to generate a random EC key pair          */         
/* 2. Parse the list and convert from EBCDIC-1047 to ASCII for       */         
/*    display.                                                       */         
/*                                                                   */         
/* NOTE: this exec requires the user executing it to have access to  */         
/*       the CSFPCI callable service which is normally restricted to */         
/*       a very small set of users. Be aware that the CSFPCI service */         
/*       is very powerful, so use it carefully. This exec does not   */         
/*       use the more powerful/dangerous rules, so it is quite safe. */         
/*                                                                   */         
/*********************************************************************/         
                                                                                
/* -=-=-=-=-=-=-=-=-=-=-=- start user fields -=-=-=-=-=-=-=-=-=-=- */           
/*-----------------------------------------------------------------*/           
/* Curve type to be generated                                      */           
/* '00'X Prime                                                     */           
/* '01'X Brainpool                                                 */           
/* '02'X Edwards                                                   */           
/* '02'X Koblitz                                                   */           
/*-----------------------------------------------------------------*/           
curve_type = '00'X;                                                             
                                                                                
/*-----------------------------------------------------------------*/           
/* Length of p in bits */                                          */           
/* '00A0'X 160 (Brainpool)                                         */           
/* '00C0'X 192 (Brainpool, Prime)                                  */           
/* '00E0'X 224 (Brainpool, Prime)                                  */           
/* '00FF'X 255 (Edwards curve25519)                                */           
/* '0100'X 256 (Brainpool, Prime, Koblitz)                         */           
/* '0140'X 320 (Brainpool)                                         */           
/* '0180'X 384 (Brainpool, Prime)                                  */           
/* '01C0'X 448 (Edwards curve448)                                  */           
/* '0200'X 512 (Brainpool)                                         */           
/* '0209'X 521 (Prime)                                             */           
/*-----------------------------------------------------------------*/           
p_length = '0209'X;                                                             
/* -=-=-=-=-=-=-=-=-=-=-=-  end user fields  -=-=-=-=-=-=-=-=-=-=- */           
/*-----------------------------------------------------------------*/           
/* DO NOT CHANGE ANYTHING BELOW THIS POINT.                        */           
/*-----------------------------------------------------------------*/           
                                                                                
/* expected results */                                                          
ExpRC = '00000000'X; ExpRS = '00000000'X;                                       
                                                                                
/* Invariant parms */                                                           
exit_data_length     = '00000000'X;                                             
exit_data            = '';                                                      
                                                                                
/*********************************************************************/         
/* Call PKA Key Token Build                                          */         
/*********************************************************************/         
return_code          = 'FFFFFFFF'X;                                             
reason_code          = 'FFFFFFFF'X;                                             
rule_array_count     = '00000001'X;                                             
rule_array           = "ECC-PAIR"                                               
KVS                  = curve_type ||,                                           
                       '00'X      ||,                                           
                       p_length   ||,                                           
                       '0000'X    ||,                                           
                       '0000'X;                                                 
KVS_length           = D2C(LENGTH(KVS),4)                                       
private_name_len     = '00000000'X;                                             
private_name         = '';                                                      
rsvd_field_len       = '00000000'X;                                             
rsvd_field           = '';                                                      
key_token_length     = D2C(3500,4)                                              
key_token            = COPIES(' ',3500)                                         
ADDRESS LINKPGM 'CSNDPKB' ,                                                     
                'return_code'      'reason_code'  ,                             
                'exit_data_length' 'exit_data'    ,                             
                'rule_array_count' 'rule_array'   ,                             
                'KVS_length'       'KVS'          ,                             
                'private_name_len' 'private_name' ,                             
                'rsvd_field_len'   'rsvd_field'   ,                             
                'rsvd_field_len'   'rsvd_field'   ,                             
                'rsvd_field_len'   'rsvd_field'   ,                             
                'rsvd_field_len'   'rsvd_field'   ,                             
                'rsvd_field_len'   'rsvd_field'   ,                             
                'key_token_length' 'key_token' ;                                
IF (return_code \= ExpRC | reason_code \= ExpRS) THEN                           
  DO;                                                                           
    SAY 'PKB: rc =' C2X(return_code) 'rs =' C2X(reason_code);                   
    SIGNAL getout;                                                              
  END;                                                                          
                                                                                
/*********************************************************************/         
/* Call PKA Key Generate                                             */         
/*********************************************************************/         
return_code          = 'FFFFFFFF'X;                                             
reason_code          = 'FFFFFFFF'X;                                             
rule_array_count     = '00000001'X;                                             
rule_array           = 'MASTER  ';                                              
regen_data_length    = '00000000'X;                                             
regen_data           = '';                                                      
skeleton_key_len     = key_token_length;                                        
skeleton_key         = key_token;                                               
transport_key        = COPIES('00'X,64);                                        
gen_key_token_len    = D2C(3500,4);                                             
gen_key_token        = COPIES(' ',3500);                                        
address linkpgm 'CSNDPKG' ,                                                     
                'return_code'       'reason_code'   ,                           
                'exit_data_length'  'exit_data'     ,                           
                'rule_array_count'  'rule_array'    ,                           
                'regen_data_length' 'regen_data'    ,                           
                'skeleton_key_len'  'skeleton_key'  ,                           
                'transport_key'                     ,                           
                'gen_key_token_len' 'gen_key_token' ;                           
IF (return_code \= ExpRC | reason_code \= ExpRS) THEN                           
  DO;                                                                           
    SAY 'PKG: rc =' C2X(return_code) 'rs =' C2X(reason_code);                   
    SIGNAL getout;                                                              
  END;                                                                          
                                                                                
/*********************************************************************/         
/* Call Digital Signature Generate                                   */         
/*********************************************************************/         
return_code          = 'FFFFFFFF'X;                                             
reason_code          = 'FFFFFFFF'X;                                             
rule_array_count     = '00000001'X;                                             
rule_array           = 'ECDSA  ';                                               
priv_key_length      = gen_key_token_len;                                       
priv_key             = gen_key_token;                                           
data_length          = '00000014'X;                                             
data                 = 'A9993E364706816ABA3E25717850C26C9CD0D89D'X;             
sig_field_length     = D2C(200,4);                                              
sig_bit_length       = '00000000'X;                                             
sig_field            = COPIES('FF'X,200);                                       
SAY 'before CSNDDSG:';                                                          
SAY '  sig_field_length = '||C2D(sig_field_length);                             
SAY '  sig_field =';                                                            
DO idx = 1 TO C2D(sig_field_length) BY 32;                                      
  x = MIN(32,C2D(sig_field_length)-idx+1);                                      
  SAY '    '||C2X(SUBSTR(sig_field,idx,x));                                     
END;                                                                            
ADDRESS LINKPGM 'CSNDDSG' ,                                                     
                'return_code'      'reason_code'    ,                           
                'exit_data_length' 'exit_data'      ,                           
                'rule_array_count' 'rule_array'     ,                           
                'priv_key_length'  'priv_key'       ,                           
                'data_length'      'data'           ,                           
                'sig_field_length' 'sig_bit_length' ,                           
                'sig_field'                         ;                           
IF (return_code \= ExpRC | reason_code \= ExpRS) THEN                           
  DO;                                                                           
    SAY 'DSG: rc =' C2X(return_code) 'rs =' C2X(reason_code);                   
    SIGNAL getout;                                                              
  END;                                                                          
SAY 'after CSNDDSG:';                                                           
SAY '  sig_field (original size) =';                                            
DO idx = 1 TO LENGTH(sig_field) BY 32;                                          
  x = MIN(32,LENGTH(sig_field)-idx+1);                                          
  SAY '    '||C2X(SUBSTR(sig_field,idx,x));                                     
END;                                                                            
SAY '  sig_field_length = '||C2D(sig_field_length);                             
SAY '  sig_field (truncated to sig_field_length) =';                            
DO idx = 1 TO C2D(sig_field_length) BY 32;                                      
  x = MIN(32,C2D(sig_field_length)-idx+1);                                      
  SAY '    '||C2X(SUBSTR(sig_field,idx,x));                                     
END;                                                                            
                                                                                
/*********************************************************************/         
/* Call Digital Signature Verify                                     */         
/*********************************************************************/         
return_code          = 'FFFFFFFF'X;                                             
reason_code          = 'FFFFFFFF'X;                                             
rule_array_count     = '00000001'X;                                             
rule_array           = 'ECDSA  ';                                               
pub_key_length       = gen_key_token_len;                                       
pub_key              = gen_key_token;                                           
data_length          = '00000014'X;                                             
data                 = 'A9993E364706816ABA3E25717850C26C9CD0D89D'X;             
ADDRESS LINKPGM 'CSNDDSV' ,                                                     
                'return_code'      'reason_code'    ,                           
                'exit_data_length' 'exit_data'      ,                           
                'rule_array_count' 'rule_array'     ,                           
                'pub_key_length'   'pub_key'        ,                           
                'data_length'      'data'           ,                           
                'sig_field_length' 'sig_field'      ;                           
IF (return_code \= ExpRC | reason_code \= ExpRS) THEN                           
  DO;                                                                           
    SAY 'DSV: rc =' C2X(return_code) 'rs =' C2X(reason_code);                   
    SIGNAL getout;                                                              
  END;                                                                          
SAY 'Everything worked!';                                                       
                                                                                
getout: ;                                                                       
EXIT;                                                                           
                                                                                
NOVALUE:                                                                        
SAY "Condition NOVALUE was raised."                                             
SAY CONDITION("D") "variable was not initialized."                              
SAY SOURCELINE(sigl)                                                            
EXIT;                                                                           
