/* REXX */                                                                      
/*********************************************************************/         
/*                                                                   */         
/*  Author: Didier Andre - IBM Systems - WSC                         */         
/*  Copyright IBM Corp. 2022                                         */         
/*                                                                   */         
/* This sample REXX is used to format SMF30 records and extract the  */         
/* Crypto Counters. The output file is in CSV format for convenient  */         
/* analysis with a spreadsheet, database software, ...               */         
/*                                                                   */         
/*  These samples are provided to assist in debug functions.         */         
/*  This source is distributed on an "as-is" basis,                  */         
/*  without any warranties either expressed or implied.              */         
/*                                                                   */         
/*********************************************************************/         
/*********************************************************************/         
/*  Initialize counters                                              */         
/*********************************************************************/         
Records_in = 1        /* current record number    */                            
Version_1_Count=0     /* Count of Version 1 SMF30 */                            
Version_2_Count=0     /* Count of Version 2 SMF30 */                            
Records_out = 0       /* count of o/p records     */                            
/*********************************************************************/         
/* Parse crypto counters equates from MACLIB - Crypto Counters ID    */         
/*********************************************************************/         
CrypCtrs_Num=0                                                                  
CrypCtrs='SMF_CrypCtrs_k'            /* Looking for EQUATE label     */         
"EXECIO 1 DISKR MACLIB"             /* Reading MACLIB IFASMFCN       */         
Eof=RC                                                                          
Do while Eof=0                                                                  
  Parse Pull MAC_record                                                         
  If Left(MAC_record,length(CrypCtrs))=CrypCtrs Then Do /* When CID  */         
    Parse Var MAC_record Name Equ Code Rest                                     
    Name=Substr(Name,length(CrypCtrs)+1)                                        
    CrypCtrs_Num=CrypCtrs_Num+1                                                 
    SMF30_CrypCtrs.Code=Name                      /* String in STEM */          
  End                                                                           
  "EXECIO 1 DISKR MACLIB"                                                       
  Eof=RC                                                                        
End                                                                             
"EXECIO 0 DISKR MACLIB (FINIS"      /* Closing MACLIB file          */          
CrypCtrs_Num = Right(CrypCtrs_Num,7,'0')                                        
/*********************************************************************/         
/* Reading SMF file unti end                                         */         
/*********************************************************************/         
do forever                                                                      
  "EXECIO 1 DISKR SMFIN" Records_in                                             
  if Records_in = 1 then                                                        
    if rc <> 0 then exit 12   /* SMF not allocated or i/o error */              
  if rc <> 0 then leave  /* no more records - exit */                           
  Records_in = Records_in + 1                                                   
  parse pull SMFIN                                                              
  /* FROM HEADER SECTION --------------------------------------------------- */ 
  SMF30RTY = Substr(SMFIN,2,1)               /* smf record type              */ 
  if C2d(SMF30RTY) <> 30 then iterate        /* only for smf(30)             */ 
  SMF30STP= Substr(SMFIN,19,2)               /* smf record subtype           */ 
  if C2d(SMF30STP) <> 4  then iterate        /* STEP TERMINATION only        */ 
  SMF30SID= Substr(SMFIN,11,4)               /* System identification       */  
  SMF30TME = Substr(SMFIN,3,4)               /* run time in hex              */ 
  SMF30TME = C2d(SMF30TME)                   /* convert to decimal           */ 
  SMF30TME = Left(SMF30TME,5)                /* seconds since midnight       */ 
  HH       = Trunc(SMF30TME/3600)            /* hours since midnight         */ 
  HH       = Right(HH,2,'0')                 /* truncate hours to 2 digits   */ 
  MM       = Trunc(SMF30TME-(HH*3600))       /* seconds since midnight       */ 
  MM       = Trunc(MM/60)                    /* minutes in the last hour     */ 
  MM       = Right(MM,2,'0')                 /* truncate minutes to 2 digits */ 
  SS       = Trunc(SMF30TME-(HH*3600))       /* seconds since midnight       */ 
  SS       = SS-(MM*60)                      /* seconds in the last minute   */ 
  SS       = Right(SS,2,'0')                 /* truncate seconds to 2 digits */ 
  SMF30TME = HH||':'||MM||':'||SS            /* time in HH:MM:SS format      */ 
  SMF30DTE = Substr(SMFIN,7,4)               /* date in packed decimal       */ 
  SMF30DTE = C2x(SMF30DTE)                   /* convert to hexadecimal       */ 
  SMF30DTE = Left(SMF30DTE,7)                /* remove sign indicator        */ 
  SMF30DTE = Right(SMF30DTE,5)               /* remove leadgin zeroes        */ 
  /* FROM SUBSYSTEM SECTION ------------------------------------------------ */ 
  SMF30SOF = Substr(SMFIN,21,4)              /* offset to subsystem section  */ 
  SMF30SOF = C2d(SMF30SOF)                   /* convert to decimal           */ 
  SMF30SOF = D2X(SMF30SOF)                   /* decimal to hex               */ 
  if SMF30SOF='DB' then                      /* Version 2 if SMF30SOF=x'DB'  */ 
    Version_2_Count=Version_2_Count+1        /*  increasve V2 counter     '  */ 
  else Version_1_Count=Version_1_Count+1     /* if not, it is Version_1_Count */
  SMF30SOF = Substr(SMFIN,21,4)              /* offset to subsystem section  */ 
  SMF30SOF = C2d(SMF30SOF)-3                 /* convert to decimal and adjust*/ 
  SMF30PFL = Substr(SMFIN,SMF30SOF+3,1)      /* offset to SMF30PFlags        */ 
  SMF30PFL = C2X(SMF30PFL)                   /* convert to hexadecimal       */ 
  SMF30PFL = X2B(SMF30PFL)                   /* hexa to binary               */ 
  If Substr(SMF30PFL,2,1)='1' Then CRYPCTRS='ON' /* If bit1 is on, we have   */ 
  Else CRYPCTRS='OFF'                            /* crypto counters          */ 
  SMF30IOF = Substr(SMFIN,29,4)              /* offset to identification sect*/ 
  SMF30IOF = C2d(SMF30IOF) - 3               /* convert to decimal and adjust*/ 
  /* FROM IDENTIFICATION SECTION ------------------------------------------- */ 
  SMF30JBN = Substr(SMFIN,SMF30IOF,8)        /* jobname                      */ 
  SMF30PGM = Substr(SMFIN,SMF30IOF+8,8)      /* program name                 */ 
  SMF30STM = Substr(SMFIN,SMF30IOF+16,8)     /* step name                    */ 
  SMF30JNM = Substr(SMFIN,SMF30IOF+32,8)     /* JES job identifier           */ 
  SMF30CLS = Substr(SMFIN,SMF30IOF+42,1)     /* job class (jobs only)        */ 
  /* FROM CRYPTO COUNTERS SECTION ------------------------------------------ */ 
  SMF30CPO = Substr(SMFIN,192-3,4)           /* Offset to the crypto count.  */ 
  SMF30CPO = C2d(SMF30CPO) - 3               /* convert to decimal and adjust*/ 
  SMF30CPL = Substr(SMFIN,196-3,2)           /* Len. of crypto counters sect.*/ 
  SMF30CPL = C2d(SMF30CPL)                   /* convert to decimal           */ 
  SMF30CPN = Substr(SMFIN,198-3,2)           /* Number of crypto sections    */ 
  SMF30CPN = C2d(SMF30CPN)                   /* convert to decimal           */ 
  If SMF30CPN>0 Then Do                      /* If we have a crypto section  */ 
    Do S=1 to SMF30CPN                       /* For each of the cypto section*/ 
     SMF30CCN = Substr(SMFIN,SMF30CPO+((S-1)*SMF30CPL),SMF30CPL) /* section# */ 
     SMF30CID = C2D(Left(SMF30CCN,2))        /* SMF30_CrypCtrs_Entry_ID      */ 
     SMF30CCC = C2D(Right(SMF30CCN,8))       /* SMF30_CrypCtrs_Count         */ 
     if SMF30CCC = 0 Then Iterate            /* Secions with counters = 0    */ 
     if Records_out = 0 then call WRITE_HEADER /* write page heading first t */ 
     call WRITE_CSV                          /* write output record in CSV   */ 
    End                                                                         
  End                                                                           
end  /* Do forever */                                                           
/*********************************************************************/         
/* Done with processing - Writing records counters                   */         
/*********************************************************************/         
Records_in = Right(Records_in-1,7,'0')                                          
Records_out = Right(Records_out,7,'0')                                          
Version_1_Count = Right(Version_1_Count,7,'0')                                  
Version_2_Count = Right(Version_2_Count,7,'0')                                  
say "----------------------------------------"                                  
say " SMF30_CrypCtrs parsed         = "CrypCtrs_Num                             
say " SMF total records read        = "Records_in                               
say " SMF30 Version1 records read   = "Version_1_Count                          
say " SMF30 Version2 records read   = "Version_2_Count                          
say " # of crypto counters reported = "Records_out                              
say "----------------------------------------"                                  
"EXECIO * DISKW REPORT"                                                         
/*********************************************************************/         
/* Done with processing - closing input/output files                 */         
/*********************************************************************/         
"EXECIO 0 DISKW REPORT (FINIS"                                                  
"EXECIO 0 DISKR SMF (FINIS"                                                     
Exit 0                                                                          
/*===================================================================*/         
/* WRITE_HEADER: Routine writing output CSV file header              */         
/*===================================================================*/         
WRITE_HEADER:                                                                   
Output_record = 'SMF30SID'                                                      
Output_record = Output_record';SMF30DTE'                                        
Output_record = Output_record';SMF30TME'                                        
Output_record = Output_record';SMF30STM'                                        
Output_record = Output_record';SMF30STM'                                        
Output_record = Output_record';SMF30PGM'                                        
Output_record = Output_record';SMF30JNM'                                        
Output_record = Output_record';SMF30CID'                                        
Output_record = Output_record';SMF30CCC'                                        
Output_record = Output_record';SMF30_CrypCtrs'                                  
Push  Output_record                                                             
"EXECIO 1 DISKW REPORT"                                                         
return                                                                          
/*===================================================================*/         
/* WRITE_CSV: Routine writing output CSV file                        */         
/*===================================================================*/         
WRITE_CSV:                                                                      
Output_record = SMF30SID                                                        
Output_record = Output_record';'SMF30DTE                                        
Output_record = Output_record';'SMF30TME                                        
Output_record = Output_record';'SMF30JBN                                        
Output_record = Output_record';'SMF30STM                                        
Output_record = Output_record';'SMF30PGM                                        
Output_record = Output_record';'SMF30JNM                                        
Output_record = Output_record';'SMF30CID                                        
Output_record = Output_record';'SMF30CCC                                        
Output_record = Output_record';'SMF30_CrypCtrs.SMF30CID                         
Push Output_record                                                              
"EXECIO 1 DISKW REPORT"                                                         
Records_out = Records_out + 1    /* increase counter */                         
return                                                                          
