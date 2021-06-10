import time
import http.server
from socketserver import ThreadingMixIn
import socket as Socket
from socketserver import BaseServer
#from OpenSSL import SSL
import threading
import string,os,sys
# from saxXacmlHandler import *
import string
import xml.sax
from xml.sax.handler import *

continueResponse = '<?xml encoding="UTF-8" version="1.0"?><Response><Result><Decision>Permit</Decision><Status></Status><Obligations><Obligation FulfillOn="Permit" ObligationId="urn:cisco:xacml:policy-attribute"><AttributeAssignment AttributeId="Policy:simplecontinue"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">&lt;cixml ver="1.0"&gt;&lt;continue&gt;&lt;/continue&gt; &lt;/cixml&gt;</AttributeValue></AttributeAssignment></Obligation></Obligations></Result></Response>'

continueWithAnnouncementResponse = '<?xml encoding="UTF-8" version="1.0"?><Response><Result><Decision>Permit</Decision><Status></Status><Obligations><Obligation FulfillOn="Permit" ObligationId="urn:cisco:xacml:policy-attribute"><AttributeAssignment AttributeId="Policy:simplecontinue"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">&lt;cixml ver="1.0"&gt;&lt;continue&gt;&lt;greeting identification="custom_05011"/&gt;&lt;/continue&gt; &lt;/cixml&gt;</AttributeValue></AttributeAssignment></Obligation></Obligations></Result></Response>'

continueWithModifyIngEdResponse = '<?xml encoding="UTF-8" version="1.0"?><Response><Result><Decision>Permit</Decision><Status></Status><Obligations><Obligation FulfillOn="Permit" ObligationId="urn:cisco:xacml:policy-attribute"><AttributeAssignment AttributeId="Policy:simplecontinue"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">&lt;cixml ver="1.0"&gt;&lt;continue&gt;&lt;modify callingnumber="1000" callednumber="61002"/&gt;&lt;/continue&gt; &lt;/cixml&gt;</AttributeValue></AttributeAssignment></Obligation></Obligations></Result></Response>'

denyResponse = '<?xml encoding="UTF-8" version="1.0"?><Response><Result><Decision>Deny</Decision><Status></Status><Obligations><Obligation FulfillOn="Deny" ObligationId="urn:cisco:xacml:response-qualifier"><AttributeAssignment AttributeId="urn:cisco:xacml:is-resource"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">resource</AttributeValue></AttributeAssignment></Obligation></Obligations></Result></Response>'

divertResponse = '<?xml encoding="UTF-8" version="1.0"?> <Response><Result><Decision>Permit</Decision><Obligations><Obligation FulfillOn="Permit" ObligationId="continue.simple"><AttributeAssignment AttributeId="Policy:continue.simple"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">&lt;cixml ver="1.0"&gt;&lt;divert&gt;&lt;destination&gt;{}&lt;/destination&gt;&lt;/divert&gt;&lt;reason&gt;chaperone&lt;/reason&gt;&lt;/cixml&gt;</AttributeValue></AttributeAssignment></Obligation></Obligations></Result></Response>'

notApplicableResponse = '<?xml encoding="UTF-8" version="1.0"?> <Response> <Result> <Decision>NotApplicable</Decision> <Status> <StatusCode Value="The PDP is not protecting the application requested for, please associate the application with the Entitlement Server in the PAP and retry"/> </Status> <Obligations> <Obligation ObligationId="PutInCache" FulfillOn="Deny"> <AttributeAssignment AttributeId="resource" DataType="http://www.w3.org/2001/XMLSchema#anyURI">CISCO:UC:VoiceOrVideoCall</AttributeAssignment> </Obligation>  </Obligations> </Result> </Response>'

indeterminateResponse = '<?xml encoding="UTF-8" version="1.0"?> :<Response><Result ResourceId=""><Decision>Indeterminate</Decision><Status><StatusCode Value="urn:cisco:xacml:status:missing-attribute"/><StatusMessage>Required subjectid,resourceid,actionid not present in the request</StatusMessage><StatusDetail>Request failed</StatusDetail></Status></Result></Response>'

class MyHandler(http.server.BaseHTTPRequestHandler):
    def setup(s):
        s.connection = s.request
        s.rfile = Socket.socket.makefile(s.request, "rb", s.rbufsize)
        s.wfile = Socket.socket.makefile(s.request, "wb", s.wbufsize)

    def do_HEAD(s):
        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.send_header("Connection", "Keep-Alive")
        s.send_header("Keep-Alive", "timeout = 20000   max = 100")
        s.end_headers()
        message =  threading.currentThread().getName()
        print("currentThread", message)

    def do_POST(s):
        message =  threading.currentThread().getName()
        print(time.asctime(), "do_POST", "currentThread", message)
        parser = xml.sax.make_parser()
        xacmlParser = XacmlHandler()
        parser.setContentHandler(xacmlParser)
        try:
            length = int(s.headers.get('content-length'))
            #print('length ', length)
            postdata = s.rfile.read(length)
            #print(postdata)
            fd = open('tempXacmlReq.xml', "w")
            fd.write(postdata.decode("utf-8"))
            fd.close()
        except:
            print('failure')
            pass

        parser.parse("tempXacmlReq.xml")

        if (xacmlParser.callingNumber() == '1000') and (xacmlParser.calledNumber() == '2000'):
            print('send response', denyResponse)
            MyHandler.send_xml(s, denyResponse)
        elif (xacmlParser.callingNumber() == '1000') and (xacmlParser.calledNumber() == '2000'):
            print('send response', continueWithAnnouncementResponse)
            MyHandler.send_xml(s, continueWithAnnouncementResponse)
        elif (xacmlParser.callingNumber() == '48123211885') and (xacmlParser.calledNumber() == '232325'):
            print(f'Diverting to 232326')
            MyHandler.send_xml(s, divertResponse.format('232326'))
        elif (xacmlParser.callingNumber() == '1000') and (xacmlParser.calledNumber() == '2000'):
            print('send response', continueWithModifyIngEdResponse)
            MyHandler.send_xml(s, continueWithModifyIngEdResponse)
        elif (xacmlParser.callingNumber() == '1000') and (xacmlParser.calledNumber() == '2000'):
            print('send response', notApplicableResponse)
            MyHandler.send_xml(s, notApplicableResponse)
        elif (xacmlParser.callingNumber() == '1000') and (xacmlParser.calledNumber() == '2000'):
            print('send response', indeterminateResponse)
            MyHandler.send_xml(s, indeterminateResponse)
        else:
            print('send response', continueResponse)
            MyHandler.send_xml(s, continueResponse)

    def send_xml(s, text, code=200):
        s.send_response(code)
        s.send_header('Content-type', 'text/xml; charset="utf-8"')
        s.send_header('Content-Length', str(len(text)))
        s.send_header("Connection", "Keep-Alive")
        s.send_header("Keep-Alive", "timeout = 20000   max = 100")
        s.end_headers()
        s.wfile.write(text.encode())
        s.wfile.flush()

class ThreadedHTTPServer(ThreadingMixIn, http.server.HTTPServer):
    threading.daemon_threads = True

class XacmlHandler(ContentHandler):
    """Crude extractor for XACML document"""
    def __init__(self):
        self.isCallingNumber = 0
        self.isCalledNumber = 0
        self.isTransformedCgpn = 0
        self.isTransformedCdpn = 0
        self.CallingNumber = 0
        self.CalledNumber = 0
        self.TransformedCgpn = 0
        self.TransformedCdpn = 0
        
    def startDocument(self):
        print('--- Begin Document ---')
        
    def startElement(self, name, attrs):
        if name == 'Attribute':
            self.attrs = attrs.get('AttributeId')
            print('AttributeId', self.attrs)
        elif name == 'AttributeValue':
            if self.attrs == 'urn:Cisco:uc:1.0:callingnumber':
                self.isCallingNumber = 1
            elif self.attrs == 'urn:Cisco:uc:1.0:callednumber':
                self.isCalledNumber = 1
            elif self.attrs == 'urn:Cisco:uc:1.0:transformedcgpn':
                self.isTransformedCgpn = 1
            elif self.attrs == 'urn:Cisco:uc:1.0:transformedcdpn':
                self.isTransformedCdpn = 1
                
    def endElement(self, name):
        if name == 'Request':
            # format xacml response based on called/calling numbers
            print('endElement Request')
            
    def characters(self, ch):
        if self.isCallingNumber == 1:
             self.CallingNumber = ch
             print('CallingNumber ' + ch)
             self.isCallingNumber = 0
        if self.isCalledNumber == 1:
             self.CalledNumber = ch
             print('CalledNubmer ' + ch)
             self.isCalledNumber = 0
        if self.isTransformedCgpn == 1:
             self.TransformedCgpn = ch
             print('TransformedCgpn ' + ch)
             self.isTransformedCgpn = 0
        if self.isTransformedCdpn == 1:
             self.TransformedCdpn = ch
             print('TransformedCdpn ' + ch)
             self.isTransformedCdpn = 0

    def callingNumber(self): return self.CallingNumber

    def calledNumber(self): return self.CalledNumber

    def transformedCgpn(self): return self.TransformedCgpn

    def transformedCdpn(self): return self.TransformedCdpn

if __name__ == '__main__':
    args = sys.argv[1:]
    REQARGS = 3
    
    if len(args) < REQARGS:
        print("Usage:",sys.argv[0], "<HOST_NAME> <PORT> http")
        sys.exit(1)

    HOST_NAME = sys.argv[1]
    PORT      = sys.argv[2]
    PORT_NUM  = int(PORT)
    PROTO     = sys.argv[3]
    
    print("HTTP://HOST_NAME:PORT", PROTO, '://', HOST_NAME, ':', PORT)

    if PROTO == 'http' or PROTO == 'HTTP':
        httpd = ThreadedHTTPServer((HOST_NAME, PORT_NUM), MyHandler)
    else:
        print('invalid proto', PROTO, 'required http')
        sys.exit(1)

    print(time.asctime(), "HTTP CURRI Server Started - %s:%s" % (HOST_NAME, PORT))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()
        sys.exit()
		
    print(time.asctime(), "Server Stopped - %s:%s" % (HOST_NAME, PORT))
