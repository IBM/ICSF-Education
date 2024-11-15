//XXXXXXXX JOB MSGLEVEL=(1,1),MSGCLASS=X,REGION=0M,                             
//  NOTIFY=&SYSUID                                                              
//*                                                                             
//********************************************************************          
//*  AUTHOR: DIDIER ANDRE - IBM SYSTEMS - WSC                        *          
//*  COPYRIGHT IBM CORP. 2022                                        *          
//*                                                                  *          
//*  This JCL reads Type 30 SMF records and formats them in a report *          
//*  using CSV format.                                               *          
//*                                                                  *          
//*   1) Add the job parameters to meet your system requirements.    *          
//*   2) Change the DUMPIN DSN=hlq.smfdata.input to be the name of   *          
//*      the dataset where you currently have SMF data being         *          
//*      recorded.                                                   *          
//*   3) Change the REPORT DSN=hlq.report.csv to be the name of the  *          
//*      dataset where the records will be extracted in CSV format   *          
//*   4) Change the SYS1.MACLIB dataset name if required             *          
//*   5) Change the SYSEXEC DSN=hlq.rexx.dataset to be the name of   *          
//*      the dataset where you have placed the SMF30CRY Rexx sample. *          
//*                                                                  *          
//********************************************************************          
//*------------------------------------------------------------------*          
//*- Delete output file prior to execution                          -*          
//*------------------------------------------------------------------*          
//DELETRPT EXEC PGM=IEFBR14                                                     
//REPORT   DD  DSN=hlq.report.csv,                                              
//         DISP=(MOD,DELETE,DELETE),                                            
//    BLKSIZE=0,SPACE=(TRK,(0,0)),RECFM=VB,LRECL=32756,UNIT=SYSDA               
//*------------------------------------------------------------------*          
//*- Sort SMF records by data/time, include only SMF30             --*          
//*------------------------------------------------------------------*          
//SORTRPT  EXEC PGM=SORT                                                        
//SYSOUT   DD SYSOUT=*                                                          
//SYSDBOUT DD SYSOUT=*                                                          
//SYSUDUMP DD SYSOUT=*                                                          
//SORTIN   DD DISP=SHR,DSN=hlq.smfdata.input                                    
//SORTOUT DD  DSN=&&FLAT30,                                                     
//    DISP=(NEW,CATLG,DELETE),                                                  
//    BLKSIZE=0,SPACE=(CYL,(10,10)),RECFM=VB,LRECL=32756,UNIT=SYSDA             
//SYSIN    DD *                                                                 
  SORT FIELDS=(11,4,CH,A,7,4,CH,A),EQUALS                                       
  INCLUDE COND=(6,1,CH,EQ,X'1E')                                                
  MODS E15=(ERBPPE15,36000,,N),E35=(ERBPPE35,3000,,N)                           
//*------------------------------------------------------------------*          
//*- Generate a CSV format file with formatted Crypto Counters      -*          
//*------------------------------------------------------------------*          
//SMF30CRY EXEC  PGM=IRXJCL,PARM='SMF30CRY'                                     
//SYSTSIN  DD  DUMMY                                                            
//SYSTSPRT DD  SYSOUT=*                                                         
//SYSEXEC  DD  DISP=SHR,DSN=hlq.rexx.dataset                                    
//MACLIB   DD  DISP=SHR,DSN=SYS1.MACLIB(IFASMFCN)                               
//SMFIN    DD  DISP=SHR,DSN=&&FLAT30                                            
//REPORT   DD  DISP=(NEW,CATLG,DELETE),                                         
//             DSN=hlq.report.csv,                                              
//             SPACE=(CYL,(1,1)),                                               
//             DCB=(LRECL=200,BLKSIZE=3990,RECFM=FB)                            
