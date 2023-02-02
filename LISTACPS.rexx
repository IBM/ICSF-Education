/* Rexx */                                                                      
SIGNAL ON NOVALUE;                                                              
/*********************************************************************/         
/*    Licensed Materials - Property of IBM.                          */         
/*    5650-ZOS                                                       */         
/*    COPYRIGHT IBM CORP. 2023                                       */         
/*                                                                   */         
/* This REXX exec will:                                              */         
/* 1. Call CSFPCI to retrieve the list of all possible ACPs, grouped */         
/*    as they are in the ICSF publications.                          */         
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
ExpRC = '00000000'X; ExpRS = '00000000'X;                                       
                                                                                
ASCII_in =,                                                                     
'202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F'X||,          
'404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F'X||,          
'606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E'X;              
EBCDIC_out =,                                                                   
' !"#$%&''()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^'||,           
'_`abcdefghijklmnopqrstuvwxyz{|}~'                                              
                                                                                
debug = 0;                                                                      
                                                                                
return_code                          = 'FFFFFFFF'X;                             
reason_code                          = 'FFFFFFFF'X;                             
exit_data_length                     = '00000000'X;                             
exit_data                            = '';                                      
rule_array_count                     = '00000001'X;                             
rule_array                           = 'ACPOINTS';                              
target_pci_coprocessor               = '00000001'X;                             
target_pci_coprocessor_serial_number = '        ';                              
request_block_length                 = '00000000'X;                             
request_block                        = '';                                      
request_data_block_length            = '00000000'X;                             
request_data_block                   = '';                                      
reply_block_length                   = '00000000'X;                             
reply_block                          = '';                                      
reply_data_block_length              = '00009C40'X;                             
reply_data_block                     = COPIES('FF'X,40000);                     
masks_length                         = '00000020'X;                             
masks_data                           = COPIES('00'X,32);                        
                                                                                
ADDRESS LINKPGM 'CSFPCI' ,                                                      
                'return_code' 'reason_code' ,                                   
                'exit_data_length' 'exit_data' ,                                
                'rule_array_count' 'rule_array' ,                               
                'target_pci_coprocessor' ,                                      
                'target_pci_coprocessor_serial_number' ,                        
                'request_block_length' 'request_block' ,                        
                'request_data_block_length' 'request_data_block' ,              
                'reply_block_length' 'reply_block' ,                            
                'reply_data_block_length' 'reply_data_block' ,                  
                'masks_length' 'masks_data' ;                                   
                                                                                
IF (return_code \= ExpRC | reason_code \= ExpRS) THEN                           
  SAY 'PCI FAILED - rc =' C2X(return_code) 'rs =' C2X(reason_code);             
else do ;                                                                       
   say 'PCI: rc =' c2x(return_code) 'rs =' c2x(reason_code) ;                   
   say 'reply_data_block_length:' c2x(reply_data_block_length) ;                
   say 'reply_data_block:' ;                                                    
   n = C2D(reply_data_block_length);                                            
   reply_data_block = LEFT(reply_data_block,n);                                 
   DO UNTIL (n = 0);                                                            
     IF (debug > 0) THEN                                                        
       DO;                                                                      
         SAY "TL: n = "||n;                                                     
         SAY "TL: LENGTH(rdb) = "||LENGTH(reply_data_block);                    
         SAY "FX= "||C2X(LEFT(reply_data_block,32));                            
       END;                                                                     
     IF (LEFT(reply_data_block,1) = '01'X) THEN                                 
       DO;                                                                      
         GROUP_ID = C2X(SUBSTR(reply_data_block,1,1));                          
         GROUP_NAME_LEN = C2D(SUBSTR(reply_data_block,2,4));                    
         GROUP_NAME_a = SUBSTR(reply_data_block,6,GROUP_NAME_LEN);              
         GROUP_NAME = TRANSLATE(GROUP_NAME_a,EBCDIC_out,ASCII_in);              
         IF (debug > 0) THEN                                                    
           DO;                                                                  
             SAY "GROUP_ID = "||GROUP_ID;                                       
             SAY "GROUP_NAME_LEN = "||GROUP_NAME_LEN;                           
           END;                                                                 
         SAY 'GROUP: '||GROUP_NAME;                                             
         IF (debug > 0) THEN                                                    
           DO;                                                                  
             SAY "GB: n = "||n;                                                 
             SAY "GB: LENGTH(rdb) = "||LENGTH(reply_data_block);                
           END;                                                                 
         n = n - (1 + 4 + GROUP_NAME_LEN);                                      
         reply_data_block = RIGHT(reply_data_block,n);                          
         IF (debug > 0) THEN                                                    
           DO;                                                                  
             SAY "GA: n = "||n;                                                 
             SAY "GA: LENGTH(rdb) = "||LENGTH(reply_data_block);                
           END;                                                                 
       END;                                                                     
     ELSE                                                                       
       DO;                                                                      
         ACP_ID = C2X(SUBSTR(reply_data_block,1,1));                            
         ACP_NUM = C2X(SUBSTR(reply_data_block,2,2));                           
         ACP_TXT_LEN = C2D(SUBSTR(reply_data_block,4,4));                       
         ACP_TXT_a = SUBSTR(reply_data_block,8,ACP_TXT_LEN);                    
         ACP_TXT = TRANSLATE(ACP_TXT_a,EBCDIC_out,ASCII_in);                    
         ACP_FLAG_X = SUBSTR(reply_data_block,(8+ACP_TXT_LEN),4);               
         IF (ACP_FLAG_X = '80000000'X) THEN                                     
           ACP_FLAG = ',FLAG';                                                  
         ELSE                                                                   
           ACP_FLAG = '';                                                       
         ACP_ENAB_CNT = C2D(SUBSTR(reply_data_block,12+ACP_TXT_LEN,4));         
         IF (ACP_ENAB_CNT > 0) THEN                                             
           ACP_ENAB = ','||,                                                    
            C2X(SUBSTR(reply_data_block,16+ACP_TXT_LEN,ACP_ENAB_CNT*2));        
         ELSE                                                                   
           ACP_ENAB = '';                                                       
         SAY 'ACP '''||ACP_NUM||'''X '||ACP_TXT||ACP_ENAB||ACP_FLAG;            
         n = n - (1 + 2 + 4 + ACP_TXT_LEN + 4 + 4 + 2*ACP_ENAB_CNT);            
         reply_data_block = RIGHT(reply_data_block,n);                          
       END;                                                                     
   END;                                                                         
END;                                                                            
                                                                                
exit;                                                                           
                                                                                
NOVALUE:                                                                        
SAY "Condition NOVALUE was raised."                                             
SAY CONDITION("D") "variable was not initialized."                              
SAY SOURCELINE(sigl)                                                            
EXIT;                                                                           
