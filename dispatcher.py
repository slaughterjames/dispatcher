#! /usr/bin/env python3
'''
Dispatcher v0.1 - Copyright 2021 James Slaughter,
This file is part of Dispatcher v0.1.

Dispatcher v0.1 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Dispatcher v0.1 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Dispatcher v0.1.  If not, see <http://www.gnu.org/licenses/>.
'''

#python import
import sys
import os
import subprocess
import re
import json
import time
import datetime
import glob
import smtplib
import email
import email.encoders
import email.header
import email.mime.base
import email.mime.multipart
import email.mime.text
import mimetypes
import imaplib
import email
import webbrowser
from email.header import decode_header
from email.message import EmailMessage
from email.policy import SMTP
#from exchangelib import DELEGATE, Account, Credentials
from collections import defaultdict
#from datetime import datetime
from array import *
from termcolor import colored

#programmer generated imports
from controller import controller
from fileio import fileio

'''
Usage()
Function: Display the usage parameters when called
'''
def Usage():
    print ('Usage: [required] [optional] --debug --help')
    print ('Example: /opt/dispatcher/dispatcher.py --debug')
    print ('Required Arguments:')
    print ('--domainlist - The list of domains to be reviewed')
    print ('--type - info should be used by default but additional types can be set in the whoisdl.conf.')
    print ('--modules - all or specific')
    print ('--outputdir - Location where keyword matches are to be deposited')
    print ('--listmodules - Prints a list of available modules and their descriptions.')
    print ('--debug - Prints verbose logging to the screen to troubleshoot issues.  Recommend piping (>>) to a text file due to the amount of text...')
    print ('--help - You\'re looking at it!')
    sys.exit(-1)

'''
ConfRead()
Function: - Reads in the dispatcher.conf config file and assigns some of the important
            variables
'''
def ConfRead():
        
    ret = 0
    intLen = 0
    FConf = fileio()
    FLOG = fileio()
    data = ''
    emailalerting = ''
    emailpassthrough = ''

    try:
        #Conf file hardcoded here
        with open('/opt/dispatcher/dispatcher.conf', 'r') as read_file:
            data = json.load(read_file)
    except:
        print ('[x] Unable to read configuration file!  Terminating...')
        FLOG.WriteLogFile(CON.logfile, '[x] Unable to read configuration file!  Terminating...\n')
        return -1
    
    CON.logfile = data['logfile']
    CON.miragelogs = data['miragelogs']
    CON.staticlogs = data['staticlogs']
    CON.smtp_server = data['smtp_server']
    CON.smtp_server_port = data['smtp_server_port']
    CON.inbound_server = data['inbound_server']
    CON.emailpassthrough = data['emailpassthrough']
    CON.email = data['email']
    CON.password = data['password']
  
    if (CON.debug == True):
        print ('[DEBUG] data: ', data)
        print ('[DEBUG] CON.logfile: ' + str(CON.logfile))
        print ('[DEBUG] CON.miragelogs: ' + str(CON.miragelogs))
        print ('[DEBUG] CON.staticlogs: ' + str(CON.staticlogs))
        print ('[DEBUG] CON.smtp_server: ' + str(CON.smtp_server))
        print ('[DEBUG] CON.smtp_server_port: ' + str(CON.smtp_server_port))
        print ('[DEBUG] CON.emailpassthrough: ' + str(CON.emailpassthrough))
        print ('[DEBUG] CON.inbound_server: ' + str(CON.inbound_server))
        print ('[DEBUG] CON.email: ' + str(CON.email))
        print ('[DEBUG] CON.password: ' + str(CON.password))

    if (len(CON.email) < 3):
        print ('[x] Please enter a valid sender e-mail address in the whoisdl.conf file.  Terminating...')
        FLOG.WriteLogFile(CON.logfile, '[x] Please enter a valid sender e-mail address in the whoisdl.conf file.  Terminating...\n')            
        print ('')
        return -1

    if (len(CON.password) < 3):
        print ('[x] Please enter a valid sender e-mail password in the whoisdl.conf file.  Terminating...')
        FLOG.WriteLogFile(CON.logfile, '[x] Please enter a valid sender e-mail password in the whoisdl.conf file.  Terminating...\n')            
        print ('')
        return -1   
         
    print ('[*] Finished configuration successfully.\n')
    FLOG.WriteLogFile(CON.logfile, '[*] Finished configuration successfully.\n')
            
    return 0

'''
Parse() - Parses program arguments
'''
def Parse(args):        
    option = ''
                    
    print ('[*] Arguments: \n')
    for i in range(len(args)):
        if args[i].startswith('--'):
            option = args[i][2:]           

            if option == 'help':
                return -1  

            if option == 'debug':
                CON.debug = True
                print (option + ': ' + str(CON.debug))

    return 0

def clean(text):
    # clean text for creating a folder
    return "".join(c if c.isalnum() else "_" for c in text)

'''
retrieve_mail()
Function: - Checks the e-mail account defined in the config file for a 
            properly formatted e-mail
'''
def retrieve_mail():
   
    try:
        FLOG.WriteLogFile(CON.logfile, '[*] Attempting to authenticate with the e-mail account...\n')
        print ('[*] Attempting to authenticate with the e-mail account...')
        # create an IMAP4 class with SSL 
        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        # authenticate
        imap.login(CON.email, CON.password)
    except Exception as e:
        print (colored('[x] Error: ' + str(e) + ' Terminating...', 'red', attrs=['bold']))
        FLOG.WriteLogFile(CON.logfile, '[x] Error: ' + str(e) + ' Terminating...\n')
        return -1

    FLOG.WriteLogFile(CON.logfile, '[*] Successfully authenticated!\n')
    print (colored('[*] Successfully authenticated!\n', 'green', attrs=['bold']))

    status, messages = imap.select("INBOX")
    # number of top emails to fetch
    N = 50
    # total number of emails
    messages = int(messages[0])
    
    if (messages < N):
        print (colored('[-] The inbox is nearly empty, changing N value...\n', 'yellow', attrs=['bold']))
        N = messages

    print ('[*] There are: ' + str(messages) + ' total messages...\n')
    print("="*100)

    for i in range(messages, messages-N, -1):
        CON.output = ''
        CON.target = ''
        CON.type = ''
        # fetch the email message by ID
        res, msg = imap.fetch(str(i), "(RFC822)")
        for response in msg:
            if isinstance(response, tuple):
                # parse a bytes email into a message object
                msg = email.message_from_bytes(response[1])
                # decode the email subject
                CON.subject, encoding = decode_header(msg["Subject"])[0]
                if isinstance(CON.subject, bytes):
                    # if it's a bytes, decode to str
                    CON.subject = CON.subject.decode(encoding)
                # decode email sender
                CON.From, encoding = decode_header(msg.get("From"))[0]
                if isinstance(CON.From, bytes):
                    CON.From = CON.From.decode(encoding)
                print('Subject:', CON.subject)
                print('From:', CON.From)

                if (CON.subject.find('Domain:')!= -1):
                    CON.type = 'domain'
                    print ('[*] This message contains a subject of interest: ' + CON.subject)
                    FLOG.WriteLogFile(CON.logfile, '[*] This message contains a subject of interest ' + CON.subject +'\n')
                    CON.target = CON.subject[8:] 
                    print('[*] Domain: ' + CON.target.strip())
                    CON.output = CON.miragelogs + CON.target.strip()

                    if (os.path.exists(CON.output)):                     
                        print (colored('[-] '+ CON.target.strip() + ' has previously been dealt with...Skipping...', 'yellow', attrs=['bold']))
                    else:
                        print (colored('[*] Forwarding to Mirage for execution...', 'green', attrs=['bold']))
                        ExecuteMirage()

                        print (colored('[*] Responding via e-mail...', 'green', attrs=['bold']))
                        send_alert('mirage')

                elif (CON.subject.find('IP:')!= -1):
                    CON.type = 'ip' 
                    print ('[*] This message contains a subject of interest: ' + CON.subject)
                    FLOG.WriteLogFile(CON.logfile, '[*] This message contains a subject of interest ' + CON.subject +'\n')
                    CON.target = CON.subject[4:]
                    print('[*] IP: ' + CON.target.strip())

                    check = re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', CON.target.strip())
                    if check:
                        print (colored('[*] IP is valid!', 'green', attrs=['bold']))
                        CON.output = CON.miragelogs + CON.target.strip()

                        if (os.path.exists(CON.output)):                     
                            print (colored('[-] '+ CON.target.strip() + ' has previously been dealt with...Skipping...', 'yellow', attrs=['bold']))
                            FLOG.WriteLogFile(CON.logfile, '[-] '+ CON.target.strip() + ' has previously been dealt with...Skipping...\n')
                        else:
                            print (colored('[*] Forwarding to Mirage for execution...', 'green', attrs=['bold']))
                            ExecuteMirage()

                            print (colored('[*] Responding via e-mail...', 'green', attrs=['bold']))
                            send_alert('mirage')
                                   
                    else:
                        print (colored('[-] IP not valid!  Skipping...', 'yellow', attrs=['bold']))

                elif ((CON.subject.find('[VTMIS]')!= -1) and (CON.subject.find('_emails')!= -1)):
                    #today = datetime.today().strftime('%Y%m%d')
                    today = str(datetime.datetime.now().strftime("%Y%m%d"))                    
                    CON.type = 'fetch'
                    print ('[*] This message contains a subject of interest: ' + CON.subject)
                    FLOG.WriteLogFile(CON.logfile, '[*] This message contains a subject of interest ' + CON.subject +'\n')
                    CON.target = CON.subject[8:72]
                    CON.rule = CON.subject[75:].strip()
                    CON.output = CON.staticlogs + today + '/' + CON.rule + '/'+ CON.target.strip()

                    if (CON.debug == True):
                        print ('Target: ' + CON.target)

                    if (os.path.exists(CON.output)):                     
                        print (colored('[-] '+ CON.target.strip() + ' has previously been dealt with...Skipping...', 'yellow', attrs=['bold']))
                        FLOG.WriteLogFile(CON.logfile, '[-] '+ CON.target.strip() + ' has previously been dealt with...Skipping...\n')
                    else:
                        print (colored('[*] Forwarding to Static for execution...', 'green', attrs=['bold']))
                        ExecuteStaticVTMIS()

                        #print (colored('[*] Responding via e-mail...', 'green', attrs=['bold']))
                        #send_alert()
                elif ((CON.subject.find('[VTMIS]')!= -1) and (CON.subject.find('blackcat_ransomware')!= -1)):
                    #today = datetime.today().strftime('%Y%m%d')
                    today = str(datetime.datetime.now().strftime("%Y%m%d"))                    
                    CON.type = 'fetch'
                    print ('[*] This message contains a subject of interest: ' + CON.subject)
                    FLOG.WriteLogFile(CON.logfile, '[*] This message contains a subject of interest ' + CON.subject +'\n')
                    CON.target = CON.subject[8:72]
                    CON.rule = CON.subject[75:].strip()
                    CON.output = CON.staticlogs + today + '/' + CON.rule + '/'+ CON.target.strip()

                    if (CON.debug == True):
                        print ('Target: ' + CON.target)

                    if (os.path.exists(CON.output)):                     
                        print (colored('[-] '+ CON.target.strip() + ' has previously been dealt with...Skipping...', 'yellow', attrs=['bold']))
                        FLOG.WriteLogFile(CON.logfile, '[-] '+ CON.target.strip() + ' has previously been dealt with...Skipping...\n')
                    else:
                        print (colored('[*] Forwarding to Static for execution...', 'green', attrs=['bold']))
                        ExecuteStaticVTMISBC()

                        #print (colored('[*] Responding via e-mail...', 'green', attrs=['bold']))
                        #send_alert()
                elif (CON.subject.find('Download:')!= -1):
                    CON.type = 'fetch'
                    print ('[*] This message contains a subject of interest: ' + CON.subject)
                    FLOG.WriteLogFile(CON.logfile, '[*] This message contains a subject of interest ' + CON.subject +'\n')
                    CON.target = CON.subject[11:].strip()
                    CON.output = CON.staticlogs + CON.target.strip()

                    if (CON.debug == True):
                        print ('Target: ' + CON.target)

                    if (os.path.exists(CON.output)):                     
                        print (colored('[-] '+ CON.target.strip() + ' has previously been dealt with...Skipping...', 'yellow', attrs=['bold']))
                        FLOG.WriteLogFile(CON.logfile, '[-] '+ CON.target.strip() + ' has previously been dealt with...Skipping...\n')
                    else:
                        print (colored('[*] Forwarding to Static for execution...', 'green', attrs=['bold']))
                        ExecuteStatic()

                        print (colored('[*] Responding via e-mail...', 'green', attrs=['bold']))
                        send_alert('static')

                print("="*100)

    try:
        print ('[*] Attempting to log out of the e-mail account...')
        # close the connection and logout
        imap.close()
        imap.logout()
    except Exception as e:
        print (colored('[x] Error: ' + str(e) + ' Terminating...', 'red', attrs=['bold']))
        FLOG.WriteLogFile(CON.logfile, '[x] Error: ' + str(e) + ' Terminating...\n')
        return -1

    FLOG.WriteLogFile(CON.logfile, '[*] Successfully logged out!\n')
    print (colored('[*] Successfully logged out!', 'green', attrs=['bold']))
    
    return 0


'''
send_alert()
Function: - Sends the alert e-mail from the address specified
            in the configuration file to potentially several addresses
            specified in the "recipients.txt" file.
'''
def send_alert(tool):
    
    FLOG = fileio()
    current_time = str(datetime.datetime.now().strftime("%I:%M%p on %B %d, %Y")) + '\n'

    print ('\r\n[*] Pulling data for e-mail body...')
    FLOG.WriteLogFile(CON.logfile, '[*] Pulling data for e-mail body...\n')

    if (tool == 'mirage'):
        bodyfile = CON.miragelogs + CON.target + '/' + CON.target + '.html'
    elif (tool == 'static'):
        bodyfile = CON.staticlogs + CON.target + '/' + CON.target + '.html'

    if (CON.debug == True):
        print ('[DEBUG] bodyfile: ' + bodyfile)

    with open(bodyfile.strip(), 'r') as bf:
        bodytext = bf.read()

    split_string = str(CON.From).split("<", 1)
    
    recipient = split_string[1] 
    recipient = recipient.replace('>', ' ')

    if (CON.debug == True):
        print (str(bodytext).replace('\n', ''))
        print ('\r\n')
        print ('CON.email: ' + CON.email)
        print ('CON.From: ' + CON.From)
        print ('recipient: ' + recipient)
        print ('CON.subject: ' + CON.subject)

    ret = 0
    micromailer_data = ''
    micromailer_output_data = ''
    print ('[*] Launching Micromailer...') 

    if (tool == 'mirage'):

        if  (CON.debug == True):
            print ('[DEBUG] ' + '/opt/micromailer/micromailer.py --recipients ' + recipient.strip() + ' --subject \'AutoMirage - ' + CON.subject + '\' --bodyfile ' +  bodyfile.strip())

        subproc = subprocess.Popen('/opt/micromailer/micromailer.py --recipients ' + recipient.strip() + ' --subject \'AutoMirage - ' + CON.subject + '\' --bodyfile ' +  bodyfile.strip(), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    elif (tool == 'static'):
        if  (CON.debug == True):
            print ('[DEBUG] ' + '/opt/micromailer/micromailer.py --recipients ' + recipient.strip() + ' --subject \'Static - ' + CON.subject + '\' --bodyfile ' +  bodyfile.strip())

        subproc = subprocess.Popen('/opt/micromailer/micromailer.py --recipients ' + recipient.strip() + ' --subject \'Static - ' + CON.subject + '\' --bodyfile ' +  bodyfile.strip(), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    for micromailer_data in subproc.stdout.readlines():
         micromailer_output_data += str(micromailer_data).strip('b\'\\n') + '\n'
             
         if  (CON.debug == True):
             print (micromailer_output_data)
    
    return 0

'''
ExecuteMirage()
Function: - Does the doing
'''
def ExecuteMirage():

    ret = 0
    mirage_data = ''
    mirage_output_data = ''
    print ('[*] Launching Mirage...') 

    #if (ret !=0 ):
    #    print ('[x] Unable to continue module execution.  Terminating...')
    #    Terminate(ret)

    subproc = subprocess.Popen('/opt/mirage/mirage.py --' + CON.type.strip() + ' --target ' + CON.target.strip() + ' --type info --modules all --nolinksummary', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for mirage_data in subproc.stdout.readlines():
         mirage_output_data += str(mirage_data).strip('b\'\\n') + '\n'
             
         if  (CON.debug == True):
             print (mirage_output_data)


    return 0

'''
ExecuteStatic()
Function: - Does the doing
'''
def ExecuteStatic():

    ret = 0
    static_data = ''
    static_output_data = ''
    print ('[*] Launching Static...') 

    #if (ret !=0 ):
    #    print ('[x] Unable to continue module execution.  Terminating...')
    #    Terminate(ret)

    if  (CON.debug == True):
        print ('[DEBUG] /opt/static/static.py --hash ' + CON.target.strip() + ' --type fetch --modules VTFetch --nolinksummary')

    subproc = subprocess.Popen('/opt/static/static.py --hash ' + CON.target.strip() + ' --type fetch --modules VTFetch --nolinksummary', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for static_data in subproc.stdout.readlines():
         static_output_data += str(static_data).strip('b\'\\n') + '\n'
             
         if  (CON.debug == True):
             print (static_output_data)

    return 0

def ExecuteStaticVTMIS():

    ret = 0
    static_data = ''
    static_output_data = ''
    print ('[*] Launching Static...') 

    #if (ret !=0 ):
    #    print ('[x] Unable to continue module execution.  Terminating...')
    #    Terminate(ret)

    if  (CON.debug == True):
        print ('[DEBUG] /opt/static/static.py --hash ' + CON.target.strip() + ' --type fetch --modules VTFetch --output ' + CON.output.strip())

    subproc = subprocess.Popen('/opt/static/static.py --hash ' + CON.target.strip() + ' --type fetch --modules VTFetch --output ' + CON.output.strip(), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for static_data in subproc.stdout.readlines():
         static_output_data += str(static_data).strip('b\'\\n') + '\n'
             
         if  (CON.debug == True):
             print (static_output_data)

    static_data = ''
    static_output_data = ''

    targetfile = ''  
    directory = os.listdir(CON.output + '/' + CON.target)

    for files in directory:
        if ((files.find('.html') == -1) and (files.find('.json') == -1)):
            if (CON.debug == True):
                print ('[DEBUG] files: ' + files)
            targetfile = files

    print ('[*] Launching Static second run...')
                   
    subproc = subprocess.Popen('/opt/static/static.py --target ' + CON.output + '/' + CON.target.strip() + '/' + targetfile + ' --type email --modules reademail --output ' + CON.output + '/static', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for static_data in subproc.stdout.readlines():
         static_output_data += str(static_data).strip('b\'\\n') + '\n'
             
         if  (CON.debug == True):
             print (static_output_data)

    return 0

def ExecuteStaticVTMISBC():

    ret = 0
    static_data = ''
    static_output_data = ''
    print ('[*] Launching Static...') 

    #if (ret !=0 ):
    #    print ('[x] Unable to continue module execution.  Terminating...')
    #    Terminate(ret)

    if  (CON.debug == True):
        print ('[DEBUG] /opt/static/static.py --hash ' + CON.target.strip() + ' --type fetch --modules VTFetch --output ' + CON.output.strip())

    subproc = subprocess.Popen('/opt/static/static.py --hash ' + CON.target.strip() + ' --type fetch --modules VTFetch --output ' + CON.output.strip(), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for static_data in subproc.stdout.readlines():
         static_output_data += str(static_data).strip('b\'\\n') + '\n'
             
         if  (CON.debug == True):
             print (static_output_data)

    static_data = ''
    static_output_data = ''

    targetfile = ''  
    directory = os.listdir(CON.output + '/' + CON.target)

    for files in directory:
        if ((files.find('.html') == -1) and (files.find('.json') == -1)):
            if (CON.debug == True):
                print ('[DEBUG] files: ' + files)
            targetfile = files

    print ('[*] Launching Static second run...')
                   
    subproc = subprocess.Popen('/opt/static/static.py --target ' + CON.output + '/' + CON.target.strip() + '/' + targetfile + ' --type \"triage pe\" --modules all --output ' + CON.output + '/static', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for static_data in subproc.stdout.readlines():
         static_output_data += str(static_data).strip('b\'\\n') + '\n'
             
         if  (CON.debug == True):
             print (static_output_data)

    return 0

'''
Terminate()
Function: - Attempts to exit the program cleanly when called  
'''     
def Terminate(exitcode):
    sys.exit(exitcode)

'''
This is the mainline section of the program and makes calls to the 
various other sections of the code
'''
if __name__ == '__main__':

    ret = 0 
    count = 0
    date = datetime.datetime.now()

    CON = controller()
    FLOG = fileio() 

    ret = Parse(sys.argv)
    if (ret == -1):
        Usage()
        Terminate(ret) 

    ret = ConfRead()    
    if (ret == -1):
        print ('[x] Terminated reading the configuration file...')
        Terminate(ret)  

    if (CON.debug == True):
        print ('[DEBUG]: ')

    print ('[*] Begining run: ' + str(datetime.datetime.now().strftime("%I:%M%p on %B %d, %Y")))
    FLOG.WriteLogFile(CON.logfile, '[*] Begining run: ' + str(datetime.datetime.now().strftime("%I:%M%p on %B %d, %Y")) + '\n')
    print ('[*] Executing Dispatcher v0.1...')
    FLOG.WriteLogFile(CON.logfile, '[*] Executing Dispatcher v0.1...\n')

    #CON.whoisdlobject = whoisdlclass(CON.debug, CON.test, CON.downloads, CON.output, CON.logfile, CON.domainlist, CON.email_attachments, CON.outputdir, CON.emailalerting, CON.alert_email)

    ret = retrieve_mail()
    
    if (ret == -1):
        print ('[x] Terminated retrieving mail...')
        Terminate(ret)     

    print ('\n[*] Program Complete: ' + str(datetime.datetime.now().strftime("%I:%M%p on %B %d, %Y")))
    FLOG.WriteLogFile(CON.logfile, '[*] Program Complete: ' + str(datetime.datetime.now().strftime("%I:%M%p on %B %d, %Y")) + '\n')
    FLOG.WriteLogFile(CON.logfile, '*******************************************************************************************\n')

    Terminate(0)

'''
END OF LINE
'''
