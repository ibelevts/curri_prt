#!/usr/local/bin/python3
from datetime import datetime as time
import http.server
import threading
import sys, os
import re
import xml.etree.ElementTree as ET
from requests_toolbelt.multipart import decoder

continueResponse = '<?xml version="1.0" encoding="UTF-8"?><Response><Result><Decision>Permit</Decision><Status></Status><Obligations><Obligation FulfillOn="Permit" ObligationId="urn:cisco:xacml:policy-attribute"><AttributeAssignment AttributeId="Policy:simplecontinue"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">&lt;cixml ver="1.0"&gt;&lt;continue&gt;&lt;/continue&gt; &lt;/cixml&gt;</AttributeValue></AttributeAssignment></Obligation></Obligations></Result></Response>'

continueWithAnnouncementResponse = '<?xml version="1.0" encoding="UTF-8"?><Response><Result><Decision>Permit</Decision><Status></Status><Obligations><Obligation FulfillOn="Permit" ObligationId="urn:cisco:xacml:policy-attribute"><AttributeAssignment AttributeId="Policy:simplecontinue"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">&lt;cixml ver="1.0"&gt;&lt;continue&gt;&lt;greeting identification="custom_05011"/&gt;&lt;/continue&gt; &lt;/cixml&gt;</AttributeValue></AttributeAssignment></Obligation></Obligations></Result></Response>'

continueWithModifyIngEdResponse = '<?xml version="1.0" encoding="UTF-8"?><Response><Result><Decision>Permit</Decision><Status></Status><Obligations><Obligation FulfillOn="Permit" ObligationId="urn:cisco:xacml:policy-attribute"><AttributeAssignment AttributeId="Policy:simplecontinue"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">&lt;cixml ver="1.0"&gt;&lt;continue&gt;&lt;modify callingnumber="1000" callednumber="61002"/&gt;&lt;/continue&gt; &lt;/cixml&gt;</AttributeValue></AttributeAssignment></Obligation></Obligations></Result></Response>'

denyResponse = '<?xml version="1.0" encoding="UTF-8"?><Response><Result><Decision>Deny</Decision><Status></Status><Obligations><Obligation FulfillOn="Deny" ObligationId="urn:cisco:xacml:response-qualifier"><AttributeAssignment AttributeId="urn:cisco:xacml:is-resource"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">resource</AttributeValue></AttributeAssignment></Obligation></Obligations></Result></Response>'

divertResponse = '<?xml version="1.0" encoding="UTF-8"?><Response><Result><Decision>Permit</Decision><Obligations><Obligation FulfillOn="Permit" ObligationId="continue.simple"><AttributeAssignment AttributeId="Policy:continue.simple"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">&lt;cixml ver="1.0"&gt;&lt;divert&gt;&lt;destination&gt;{}&lt;/destination&gt;&lt;/divert&gt;&lt;reason&gt;chaperone&lt;/reason&gt;&lt;/cixml&gt;</AttributeValue></AttributeAssignment></Obligation></Obligations></Result></Response>'

notApplicableResponse = '<?xml version="1.0" encoding="UTF-8"?><Response> <Result><Decision>NotApplicable</Decision> <Status> <StatusCode Value="The PDP is not protecting the application requested for, please associate the application with the Entitlement Server in the PAP and retry"/> </Status> <Obligations> <Obligation ObligationId="PutInCache" FulfillOn="Deny"> <AttributeAssignment AttributeId="resource" DataType="http://www.w3.org/2001/XMLSchema#anyURI">CISCO:UC:VoiceOrVideoCall</AttributeAssignment> </Obligation>  </Obligations> </Result> </Response>'

indeterminateResponse = '<?xml version="1.0" encoding="UTF-8"?><Response><Result ResourceId=""><Decision>Indeterminate</Decision><Status><StatusCode Value="urn:cisco:xacml:status:missing-attribute"/><StatusMessage>Required subjectid,resourceid,actionid not present in the request</StatusMessage><StatusDetail>Request failed</StatusDetail></Status></Result></Response>'

class request_handler(http.server.BaseHTTPRequestHandler):

    def log_request(self, code): 
        pass

    def do_HEAD(s):
        try:
            s.send_response(200)
            s.send_header("Content-type", "text/html")
            s.send_header("Connection", "Keep-Alive")
            s.send_header("Keep-Alive", "timeout = 20000   max = 100")
            s.end_headers()
        except TimeoutError as error:
            print(error)
            pass

    def do_POST(s):
        if s.path == '/prt':
            request_id = f'{time.now().strftime("%Y-%m-%d_%H-%M-%S")} PRT POST from {s.client_address[0]}:{s.client_address[1]}'
            postdata = s.rfile.read(int(s.headers.get('Content-Length')))
            parts = decoder.MultipartDecoder(postdata, s.headers.get('content-type')).parts
            try:
                filename = re.search('filename="(.+?)"', parts[3].headers[b'Content-Disposition'].decode('utf-8')).group(1)
            except AttributeError:
                filename = f'prt-{time.now().strftime("%Y%m%d-%H%M%S")}-{parts[0].text[5:]}.tar.gz'
            fd = open(f'Reports/{filename}', "wb")
            fd.write(parts[3].content)
            fd.close()
            s.handle_expect_100()
            s.send_response(200)
            s.send_header("Connection", "close")
            s.end_headers()
            s.close_connection
            print(request_id, f'Processed PRT from {parts[0].text[2:]}')
            return
        elif s.path == '/pdp/AuthenticationEndPoint':
            request_id = f'{time.now().strftime("%Y-%m-%d_%H-%M-%S")} CURRI request from {s.client_address[0]}:{s.client_address[1]}'
            postdata = s.rfile.read(int(s.headers.get('Content-Length')))
            root = ET.fromstring(postdata.decode("utf-8"))[0]
            for element in root:
                if element.attrib['AttributeId'].split(':')[-1] == 'callingnumber':
                    number_a = element[0].text
                elif element.attrib['AttributeId'].split(':')[-1] == 'callednumber':
                    number_b = element[0].text
                else:
                    continue
            if number_a == '48123211885' and number_b == '232325':
                action_string = f' Diverting {number_a} calling {number_b} to 232326'
                request_handler.send_xml(s, divertResponse.format('232326'))
                print(request_id, action_string)
            else:
                action_string = f' No specific action defined for {number_a} calling {number_b}, allow proceeding'
                request_handler.send_xml(s, continueResponse)
                print(request_id, action_string)
            return
        else:
            print('Not defined')
            return

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
        if s.path == '/favicon.ico':
            return
        request_id = f'{time.now().strftime("%Y-%m-%d_%H-%M-%S")} GET from {s.client_address[0]}:{s.client_address[1]}'
        s.send_response(code=200)
        s.send_header('Content-type', 'text/html; charset="utf-8"')
        s.send_header('Content-Length', str(len('<html><head><title>CURRI_SRV</title></head><body><p>It works!</p></body></html>')))
        s.send_header("Connection", "Keep-Alive")
        s.send_header("Keep-Alive", "timeout = 20000   max = 100")
        s.end_headers()
        s.wfile.write('<html><head><title>CURRI_SRV</title></head><body><p>It works!</p></body></html>'.encode())
        s.wfile.flush()  
        print(request_id)
        return  

class ThreadedHTTPServer(http.server.ThreadingHTTPServer):
    threading.daemon_threads = True


if __name__ == '__main__':
    args = sys.argv[1:]
    REQARGS = 2
    
    if len(args) < REQARGS:
        print("Usage:",sys.argv[0], "<HOST_NAME> <PORT>")
        sys.exit(1)

    HOST_NAME = sys.argv[1]
    PORT      = sys.argv[2]
    PORT_NUM  = int(PORT)

    prtdir = os.path.dirname('Reports/') # Creates folder and the file for corrected devices logging (if doesn't exists)
    if not os.path.exists(prtdir):
        os.makedirs(prtdir)

    
    #print(f'http://{HOST_NAME}:{PORT}')
    httpd = ThreadedHTTPServer((HOST_NAME, PORT_NUM), request_handler)


    print(time.now().strftime("%Y-%m-%d_%H-%M-%S"), "HTTP CURRI/PRT Server Started - %s:%s" % (HOST_NAME, PORT))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()
        print('\nShutting down...')
        print(time.now().strftime("%Y-%m-%d_%H-%M-%S"), "Server Stopped - %s:%s" % (HOST_NAME, PORT))
        sys.exit()
		
