/* Rexx */                                                                      
                                                                                
/*-------------------------------------------------------------------*/         
/* Description: Archive a key record in the CKDS                     */         
/*-------------------------------------------------------------------*/         
/* Set the expected return and reason code     */
Exp_RC = '00000000'x;
Exp_RS = '00000000'x;

/* Set the label of desired key to be archived */
ARCHIVE_KEY_LABEL = "KEY#LABEL#TO#BE#ARCHIVED";

/*-------------------------------------------------------------------*/
/* The 'metadata_list' parameter contains one or more blocks used by */
/* the KDMW service to determine which metadata attributes should be */
/* changed for a key label(s).                                       */
/*                                                                   */
/* In this case the attribute we wish to change is the archive flag, */
/* and we wish to set this flag to 'true'. Below we will construct   */
/* a metadata block to accomplish this.                              */
/*-------------------------------------------------------------------*/
metadata_list = d2c(5,2) ||, /* Length of the block in bytes         */
                '0009'x  ||, /* Type of metadata to be written       */
                '01'x;       /* The value we wish to set the         */
                             /* attribute to, in this case, true     */

/*-------------------------------------------------------------------*/
/* We intend to archive a key in the CKDS, so set the CKDS rule in   */
/* the rule array for KDMW                                           */
/*-------------------------------------------------------------------*/
rule_array           = 'CKDS    ' ;

/*-------------------------------------------------------------------*/
/* The 'label_list' parameter contains one or more labels which we   */
/* intend to update the metadata for. Each label in this list must   */
/* be padded on the right with blanks up to the maximum length.      */
/*                                                                   */
/* N.B. label lengths are different depending upon the KDS being     */
/* used:                                                             */
/*   - CKDS labels are 72 bytes                                      */
/*   - PKDS labels are 64 bytes                                      */
/*   - TKDS labels are 44 bytes                                      */
/* We are using the CKDS, so we pad out 72 bytes. We have only one   */
/* label in the list, so we set the count to 1.                      */
/*-------------------------------------------------------------------*/
label_list  = LEFT(ARCHIVE_KEY_LABEL,72);
label_count = '00000001'X;

/* Call the KDS Metadata Write service */
CALL CSFKDMW;                                                                 

EXIT ;                                                                          
                                                                                
/*------------------------------------------------------------------*/          
/* Key Data Set Metadata Write                                      */          
/*------------------------------------------------------------------*/
/* This routine invokes the KDMW service. The service has many      */
/* parameters which are either constant between calls or can be     */
/* derived from parameters we have set previously, so we allow this */
/* routine to handle the other parameters for us.                   */
/*------------------------------------------------------------------*/
CSFKDMW:                                                                        
                                                                                
/* initialize parameter list */                                                 
DMW_rc               = 'FFFFFFFF'x ;                                            
DMW_rs               = 'FFFFFFFF'x ;                                            
exit_data_length     = '00000000'x ;                                            
exit_data            = '' ;                                                     
rule_array_count     = d2c(1,4) ;                                               
metadata_list_length = d2c(length(metadata_list),4) ;                           
results_list         = d2c(32,4) ;                                              
reserved1_length     = '00000000'x ;                                            
reserved1            = '' ;                                                     
reserved2_length     = '00000000'x ;                                            
reserved2            = '' ;                                                     
                                                                                
/* CALL CSFKDMW */                                                              
ADDRESS LINKPGM 'CSFKDMW'               ,                                       
 'DMW_rc' 'DMW_rs'                      ,                                       
 'exit_data_length'     'exit_data'     ,                                       
 'rule_array_count'     'rule_array'    ,                                       
 'label_count'          'label_list'    ,                                       
 'metadata_list_length' 'metadata_list' ,                                       
 'results_list'                         ,                                       
 'reserved1_length'     'reserved1'     ,                                       
 'reserved2_length'     'reserved2'     ;                                       
                                                                                
                                                                                
IF (DMW_Rc /= Exp_Rc) THEN                                                      
  SAY 'DMW failed: rc =' c2x(DMW_rc) 'rs =' c2x(DMW_rs) ;                       
ELSE                                                                            
 DO ;                                                                           
  results_list = ,                                                              
    substr(results_list,1,c2d(metadata_list_length)) ;                          
  SAY 'DMW: rc =' c2x(DMW_rc) 'rs =' c2x(DMW_rs) ;                              
 END ;                                                                          
                                                                                
DMW_end:                                                                        
RETURN ;                                                                        
