#!/usr/local/bin/python3
import time
import http.server
import socket
import threading
import sys
import xml.etree.ElementTree as ET
from requests_toolbelt.multipart import decoder

continueResponse = '<?xml version="1.0" encoding="UTF-8"?><Response><Result><Decision>Permit</Decision><Status></Status><Obligations><Obligation FulfillOn="Permit" ObligationId="urn:cisco:xacml:policy-attribute"><AttributeAssignment AttributeId="Policy:simplecontinue"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">&lt;cixml ver="1.0"&gt;&lt;continue&gt;&lt;/continue&gt; &lt;/cixml&gt;</AttributeValue></AttributeAssignment></Obligation></Obligations></Result></Response>'

continueWithAnnouncementResponse = '<?xml version="1.0" encoding="UTF-8"?><Response><Result><Decision>Permit</Decision><Status></Status><Obligations><Obligation FulfillOn="Permit" ObligationId="urn:cisco:xacml:policy-attribute"><AttributeAssignment AttributeId="Policy:simplecontinue"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">&lt;cixml ver="1.0"&gt;&lt;continue&gt;&lt;greeting identification="custom_05011"/&gt;&lt;/continue&gt; &lt;/cixml&gt;</AttributeValue></AttributeAssignment></Obligation></Obligations></Result></Response>'

continueWithModifyIngEdResponse = '<?xml version="1.0" encoding="UTF-8"?><Response><Result><Decision>Permit</Decision><Status></Status><Obligations><Obligation FulfillOn="Permit" ObligationId="urn:cisco:xacml:policy-attribute"><AttributeAssignment AttributeId="Policy:simplecontinue"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">&lt;cixml ver="1.0"&gt;&lt;continue&gt;&lt;modify callingnumber="1000" callednumber="61002"/&gt;&lt;/continue&gt; &lt;/cixml&gt;</AttributeValue></AttributeAssignment></Obligation></Obligations></Result></Response>'

denyResponse = '<?xml version="1.0" encoding="UTF-8"?><Response><Result><Decision>Deny</Decision><Status></Status><Obligations><Obligation FulfillOn="Deny" ObligationId="urn:cisco:xacml:response-qualifier"><AttributeAssignment AttributeId="urn:cisco:xacml:is-resource"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">resource</AttributeValue></AttributeAssignment></Obligation></Obligations></Result></Response>'

divertResponse = '<?xml version="1.0" encoding="UTF-8"?> <Response><Result><Decision>Permit</Decision><Obligations><Obligation FulfillOn="Permit" ObligationId="continue.simple"><AttributeAssignment AttributeId="Policy:continue.simple"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">&lt;cixml ver="1.0"&gt;&lt;divert&gt;&lt;destination&gt;{}&lt;/destination&gt;&lt;/divert&gt;&lt;reason&gt;chaperone&lt;/reason&gt;&lt;/cixml&gt;</AttributeValue></AttributeAssignment></Obligation></Obligations></Result></Response>'

notApplicableResponse = '<?xml version="1.0" encoding="UTF-8"?> <Response> <Result> <Decision>NotApplicable</Decision> <Status> <StatusCode Value="The PDP is not protecting the application requested for, please associate the application with the Entitlement Server in the PAP and retry"/> </Status> <Obligations> <Obligation ObligationId="PutInCache" FulfillOn="Deny"> <AttributeAssignment AttributeId="resource" DataType="http://www.w3.org/2001/XMLSchema#anyURI">CISCO:UC:VoiceOrVideoCall</AttributeAssignment> </Obligation>  </Obligations> </Result> </Response>'

indeterminateResponse = '<?xml version="1.0" encoding="UTF-8"?> :<Response><Result ResourceId=""><Decision>Indeterminate</Decision><Status><StatusCode Value="urn:cisco:xacml:status:missing-attribute"/><StatusMessage>Required subjectid,resourceid,actionid not present in the request</StatusMessage><StatusDetail>Request failed</StatusDetail></Status></Result></Response>'

class curri_handler(http.server.BaseHTTPRequestHandler):
    def setup(s):
        s.connection = s.request
        s.rfile = socket.socket.makefile(s.request, "rb", s.rbufsize)
        s.wfile = socket.socket.makefile(s.request, "wb", s.wbufsize)

    def do_HEAD(s):
        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.send_header("Connection", "Keep-Alive")
        s.send_header("Keep-Alive", "timeout = 20000   max = 100")
        s.end_headers()
        message =  threading.currentThread().getName()

    def do_POST(s):
        if s.path == '/pdp/AuthenticationEndPoint':
            print('CURRI request')
            pass
        else:
            message =  threading.currentThread().getName()
            print(time.asctime(), "do_POST", "currentThread", message, 'from', s.client_address[0], s.path)
            content_type = s.headers.get('content-type')
            length = int(s.headers.get('content-length'))
            postdata = s.rfile.read(length)
            parts = decoder.MultipartDecoder(postdata, content_type).parts
            filename = parts[3].headers[b'Content-Disposition'].decode('utf-8').split('; ')[2].split('"')[1]
            print(parts[0].text)
            fd = open(filename, "wb")
            fd.write(parts[3].content)
            fd.close()
            return
        message =  threading.currentThread().getName()
        print(time.asctime(), "do_POST", "currentThread", message, 'from', s.client_address[0], s.path)
        length = int(s.headers.get('content-length'))
        postdata = s.rfile.read(length)
        root = ET.fromstring(postdata.decode("utf-8"))[0]
        for element in root:
            if element.attrib['AttributeId'].split(':')[-1] == 'callingnumber':
                if element[0].text == '48123211885':
                    print(f'Diverting caller {element[0].text} to 232326')
                    curri_handler.send_xml(s, divertResponse.format('232326'))
                else:
                    print('No specific action defined, allow proceeding')
                    curri_handler.send_xml(s, continueResponse)

    def send_xml(s, text, code=200):
        s.send_response(code)
        s.send_header('Content-type', 'text/xml; charset="utf-8"')
        s.send_header('Content-Length', str(len(text)))
        s.send_header("Connection", "Keep-Alive")
        s.send_header("Keep-Alive", "timeout = 20000   max = 100")
        s.end_headers()
        s.wfile.write(text.encode())
        s.wfile.flush()

    def do_GET(s):
        print(s.path)
        s.send_response(code=200)
        s.send_header('Content-type', 'text/xml; charset="utf-8"')
        s.send_header('Content-Length', str(len('This is a test message')))
        s.send_header("Connection", "Keep-Alive")
        s.send_header("Keep-Alive", "timeout = 20000   max = 100")
        s.end_headers()
        s.wfile.write('<html><head><title>Simple Python Http Server</title></head><body><p>This is a test.</p></body></html>'.encode())
        s.wfile.flush()    

class ThreadedHTTPServer(http.server.ThreadingHTTPServer):
    threading.daemon_threads = True


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
        httpd = ThreadedHTTPServer((HOST_NAME, PORT_NUM), curri_handler)
    else:
        print('invalid proto', PROTO, 'required http')
        sys.exit(1)

    print(time.asctime(), "HTTP CURRI Server Started - %s:%s" % (HOST_NAME, PORT))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()
        print('\nShutting down...')
        sys.exit()
		
    print(time.asctime(), "Server Stopped - %s:%s" % (HOST_NAME, PORT))
