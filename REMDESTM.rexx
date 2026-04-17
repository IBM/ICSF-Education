/* REXX REMDESTM                                                     */         
SIGNAL ON NOVALUE;                                                              
                                                                                
/*********************************************************************/         
/*                                                                   */         
/*  Licensed Materials - Property of IBM                             */         
/*  5655-ZOS                                                         */         
/*  Copyright IBM Corp. 2024, 2026                                   */         
/*                                                                   */         
/* This sample REXX accepts one or two labels, reads the token from  */         
/* the first label, checks for CDMF or DES KEK token marks, removes  */         
/* the DES KEK token mark if present, and writes the updated token   */         
/* to the second label if one was provided.                          */         
/*                                                                   */         
/* Requirements:                                                     */         
/* - READ access to CSFKRR2 profile in CSFSERV SAF class             */         
/* - appropriate access to the SAF profile in the CSFKEYS class      */         
/*   covering each label                                             */         
/* - READ access to CSFKRC2 profile in CSFSERV SAF class             */         
/*   (if a second label, different from the first, is provided)      */         
/* - READ access to CSFKRW profile in CSFSERV SAF class              */         
/*   (if a second label, same as the first, is provided)             */         
/*                                                                   */         
/*  These samples are provided to assist in debug functions.         */         
/*  This source is distributed on an "as-is" basis,                  */         
/*  without any warranties either expressed or implied.              */         
/*                                                                   */         
/* Example invocations:                                              */         
/* - If only one label is specified:                                 */         
/*   EX 'execlib(REMDESTM)' 'INPUT.LABEL'                            */         
/* - If twos label are specified:                                    */         
/*   EX 'execlib(REMDESTM)' 'INPUT.LABEL OUTPUT.LABEL'               */         
/*                                                                   */         
/* NOTES:                                                            */         
/* 1. We only remove the DES KEK token mark. If the CDMF mark is     */         
/*    present, we will not change that.                              */         
/* 2. It is strongly recommended that you specify a different label  */         
/*    for output until you can confirm that the updated key token    */         
/*    behaves as expected.                                           */         
/* 3. Unless you specify the same label for both input and output,   */         
/*    the output label must not exist.                               */         
/*                                                                   */         
/*********************************************************************/         
PARSE ARG input_label output_label ;                                            
                                                                                
input_label = STRIP(input_label);                                               
IF input_label = '' THEN                                                        
  DO;                                                                           
    SAY 'No input label was specified.';                                        
    EXIT;                                                                       
  END;                                                                          
SAY 'input_label  = "'||input_label||'"';                                       
IF output_label <> '' THEN                                                      
  DO;                                                                           
    output_label = STRIP(output_label);                                         
    SAY 'output_label = "'||output_label||'"';                                  
  END;                                                                          
ELSE                                                                            
  SAY 'output_label was not specified';                                         
SAY '';                                                                         
                                                                                
NUMERIC DIGITS 12                                                               
                                                                                
/* ICSF return codes */                                                         
RC_OK                    = '00000000'X;                                         
RC_MINOR_ERROR           = '00000004'X;                                         
RC_APPLICATION_ERROR     = '00000008'X;                                         
/* ICSF reason codes */                                                         
RS_0_OK                  = '00000000'X;                                         
RS_0_CKDS_NULL_RECORD    = '00000008'X;                                         
RS_4_CKDS_CLEAR_TOKEN    = '0000081E'X;                                         
RS_8_KEY_NOT_FOUND       = '0000271C'X;                                         
RS_8_FAILED_RACF_SERVICE = '00003E80'X;                                         
RS_8_FAILED_RACF         = '00003E84'X;                                         
RS_8_DUPLICATE_KEY_LABEL = '00003EA4'X;                                         
                                                                                
DES_KEY_VERSION0 = '00'X                                                        
DES_KEY_VERSION1 = '01'X                                                        
AES_KEY_VERSION  = '04'X                                                        
VSYM_KEY_VERSION = '05'X                                                        
                                                                                
/*********************************************************************/         
/* Attempt to read the key token by label.                           */         
/* The return/reason code will tell us what we want to know without  */         
/* revealing the key material.                                       */         
/*********************************************************************/         
return_code              = 'FFFFFFFF'X;                                         
reason_code              = 'FFFFFFFF'X;                                         
exit_data_length         = '00000000'X;                                         
exit_data                = '';                                                  
rule_array_count         = '00000000'X;                                         
rule_array               = '';                                                  
key_label                = LEFT(input_label,64);                                
key_token_length         = D2C(725,4);                                          
key_token                = COPIES('Z',725);                                     
ADDRESS LINKPGM 'CSNBKRR2'                       ,                              
                'return_code'      'reason_code' ,                              
                'exit_data_length' 'exit_data'   ,                              
                'rule_array_count' 'rule_array'  ,                              
                'key_label'                      ,                              
                'key_token_length' 'key_token'   ;                              
key_token = LEFT(key_token,C2D(key_token_length));                              
                                                           /* rc/rsn */         
IF ((return_code = RC_OK) &,                               /* 0/8    */         
    (reason_code = RS_0_CKDS_NULL_RECORD)) THEN                                 
  DO;                                                                           
    SAY 'Label '||input_label||' is a NULL token.';                             
    SAY 'There is nothing to do. Exiting.';                                     
    EXIT;                                                                       
  END;                                                                          
IF ((return_code = RC_MINOR_ERROR) &,                      /* 4/81E  */         
    (reason_code = RS_4_CKDS_CLEAR_TOKEN)) THEN                                 
  DO;                                                                           
    SAY 'Label '||input_label||' is a clear key token.';                        
    SAY 'There is nothing to do. Exiting.';                                     
    EXIT;                                                                       
  END;                                                                          
IF ((return_code = RC_APPLICATION_ERROR) &,                /* 8/271C */         
    (reason_code = RS_8_KEY_NOT_FOUND)) THEN                                    
  DO;                                                                           
    SAY 'Label '||input_label||' was not found.';                               
    SAY 'There is nothing to do. Exiting.';                                     
    EXIT;                                                                       
  END;                                                                          
IF ((return_code = RC_APPLICATION_ERROR) &,                /* 8/3E80 */         
    (reason_code = RS_8_FAILED_RACF_SERVICE)) THEN                              
  DO;                                                                           
    SAY 'Not authorized to resource CSFKRR2 in class CSFSERV.';                 
    SAY 'Exiting.';                                                             
    EXIT;                                                                       
  END;                                                                          
IF ((return_code = RC_APPLICATION_ERROR) &,                /* 8/3E84 */         
    (reason_code = RS_8_FAILED_RACF)) THEN                                      
  DO;                                                                           
    SAY 'TSO user not authorized to resource '||input_label||,                  
        ' in class CSFKEYS.';                                                   
    SAY 'Exiting.';                                                             
    EXIT;                                                                       
  END;                                                                          
ELSE IF ((return_code <> RC_OK) |,                         /* ?/?    */         
         (reason_code <> RS_0_OK)) THEN                                         
  DO;                                                                           
    SAY 'CSFKRR2 unexpected error: rc = '||C2X(return_code)||,                  
                                 ' rs = '||C2X(reason_code);                    
    SAY 'Exiting.';                                                             
    EXIT;                                                                       
  END;                                                                          
                                                                                
/* We got a token back */                                                       
key_version = SUBSTR(key_token,5,1);                                            
IF (key_version = VSYM_KEY_VERSION) THEN                                        
  DO;                                                                           
    SAY 'Label '||input_label||' is a var-len key token.';                      
    SAY 'There is nothing to do. Exiting.';                                     
    EXIT;                                                                       
  END;                                                                          
IF (key_version = AES_KEY_VERSION) THEN                                         
  DO;                                                                           
    SAY 'Label '||input_label||' is a fixed-len AES key token.';                
    SAY 'There is nothing to do. Exiting.';                                     
    EXIT;                                                                       
  END;                                                                          
IF (key_version <> DES_KEY_VERSION0) &,                                         
   (key_version <> DES_KEY_VERSION1) THEN                                       
  DO;                                                                           
    SAY 'Label '||input_label||' is a TR31 key block.';                         
    SAY 'There is nothing to do. Exiting.';                                     
    EXIT;                                                                       
  END;                                                                          
                                                                                
/* It must be a DES V0 or V1 token. */                                          
IF LENGTH(key_token) <> 64 THEN                                                 
  DO;                                                                           
    /* Not sure how this could happen but it's always worth being               
       extra careful.                                                */         
    SAY 'Length of returned token is not 64.';                                  
    SAY 'Exiting.';                                                             
    EXIT;                                                                       
  END;                                                                          
SAY 'CSNBKRR2('||input_label||') returned:';                                    
DO idx = 1 TO LENGTH(key_token) BY 32;                                          
  x = MIN(32,LENGTH(key_token)-idx+1);                                          
  SAY '  '||C2X(SUBSTR(key_token,idx,x));                                       
END;                                                                            
SAY '';                                                                         
/* First, see if the DES KEK token mark is present.                  */         
token_marks = SUBSTR(key_token,60,1);                                           
IF BITAND(token_marks,'80'X) = '80'X THEN                                       
  DO;                                                                           
    /* The CDMF token mark is on.                                    */         
    SAY 'The CDMF token mark is on.';                                           
    SAY 'Not changing the token. Exiting.';                                     
    EXIT;                                                                       
  END;                                                                          
IF BITAND(token_marks,'40'X) = '00'X THEN                                       
  DO;                                                                           
    /* The DES KEK token mark isn't on.                              */         
    SAY 'The DES KEK token mark is not on.';                                    
    SAY 'There is nothing to do. Exiting.';                                     
    EXIT;                                                                       
  END;                                                                          
/* Turn off the DES KEK token mark */                                           
token_marks = BITAND(token_marks,'BF'X);                                        
key_token = OVERLAY(token_marks,key_token,60);                                  
/* recalculate the TVV:                                                         
   TVV is 2s complement sum of first 15 words with no carry */                  
tvv = 0;                                                                        
DO idx = 1 TO 15;                                                               
  tvv = tvv + C2D(SUBSTR(key_token,(idx-1)*4+1,4));                             
END;                                                                            
tvvX = D2C(tvv,4);                                                              
key_token = OVERLAY(tvvX,key_token,61);                                         
SAY 'updated token (with DES KEK token mark removed):';                         
SAY '  '||C2X(LEFT(key_token,32));                                              
SAY '  '||C2X(RIGHT(key_token,32));                                             
SAY '';                                                                         
                                                                                
IF output_label = '' THEN                                                       
  DO;                                                                           
    SAY 'No output label specified. No CKDS update attempted.';                 
    EXIT;                                                                       
  END;                                                                          
                                                                                
IF output_label = input_label THEN                                              
  DO;                                                                           
    return_code          = 'FFFFFFFF'X;                                         
    reason_code          = 'FFFFFFFF'X;                                         
    /* key_token was already set */                                             
    key_label            = LEFT(output_label,64);                               
    ADDRESS LINKPGM 'CSNBKRW' ,                                                 
                    'return_code'      'reason_code' ,                          
                    'exit_data_length' 'exit_data'   ,                          
                    'key_token'        'key_label'   ;                          
    IF (return_code <> RC_OK) | (reason_code <> RS_0_OK) THEN                   
      DO;                                                                       
        SAY 'CSNBKRW('||output_label||') was unsuccessful:';                    
        SAY '  rc = '||C2X(return_code)||,                                      
             ' rs = '||C2X(reason_code);                                        
        EXIT;                                                                   
      END;                                                                      
    SAY 'CSNBKRW('||output_label||') was successful';                           
  END;                                                                          
ELSE                                                                            
  DO;                                                                           
    return_code          = 'FFFFFFFF'X;                                         
    reason_code          = 'FFFFFFFF'X;                                         
    rule_array_count     = '00000000'X;                                         
    rule_array           = '';                                                  
    key_label            = LEFT(output_label,64);                               
    key_token_length     = D2C(LENGTH(key_token),4);                            
    /* key_token was already set */                                             
    ADDRESS LINKPGM 'CSNBKRC2' ,                                                
                    'return_code'      'reason_code' ,                          
                    'exit_data_length' 'exit_data'   ,                          
                    'rule_array_count' 'rule_array'  ,                          
                    'key_label'                      ,                          
                    'key_token_length' 'key_token'   ;                          
    IF ((return_code = RC_APPLICATION_ERROR) &,            /* 8/3EA4 */         
        (reason_code = RS_8_DUPLICATE_KEY_LABEL)) THEN                          
      DO;                                                                       
        SAY 'CSNBKRC2('||output_label||') failed: label already exists';        
        EXIT;                                                                   
      END;                                                                      
    IF (return_code <> RC_OK) | (reason_code <> RS_0_OK) THEN                   
      DO;                                                                       
        SAY 'CSNBKRC2('||output_label||') was unsuccessful:';                   
        SAY '  rc = '||C2X(return_code)||,                                      
             ' rs = '||C2X(reason_code);                                        
        EXIT;                                                                   
      END;                                                                      
    SAY 'CSNBKRC2('||output_label||') was successful';                          
  END;                                                                          
                                                                                
EXIT;                                                                           
                                                                                
NOVALUE:                                                                        
SAY "Condition NOVALUE was raised."                                             
SAY CONDITION("D") "variable was not initialized."                              
SAY SOURCELINE(sigl)                                                            
EXIT;                                                                           
