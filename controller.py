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

'''
controller.py - 
'''

#python imports
import imp
import sys
from array import *

#programmer generated imports


'''
controller
Class: This class is responsible for maintaining key variable values globally
'''
class controller:
    '''
    Constructor
    '''
    def __init__(self):

        self.debug = False
        self.logfile = ''
        self.miragelogs = ''
        self.staticlogs = ''
        self.dispatcherobject = ''
        self.smtp_server = ''
        self.smtp_server_port = ''
        self.emailpassthrough = False
        self.inbound_server = ''
        self.email = ''
        self.email_subject = ''
        self.testemail_subject = ''
        self.password = ''
        self.output = ''
        self.target = ''
        self.type = ''
        self.subject = ''
        self.From = ''
        self.rule = ''
        #self.alert_email = []
        #self.target_list = ''
        #self.recipient_list = ''
        #self.email_attachments = []
        #self.outputdir = ''
        #self.listmodules = ''
        #self.module_manifest = []
        #self.add = False
        #self.add_line = ''
