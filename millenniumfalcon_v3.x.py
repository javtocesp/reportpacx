import sys
from bs4 import BeautifulSoup
import subprocess
import time
import datetime
from sqlalchemy import create_engine, MetaData
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Table, MetaData
import requests
import socket
import os

Firewall_list=os.environ['FW']

PA_KEY=os.environ['PA_KEY']
USER_DB=os.environ['USER_DB']
PASS_DB=os.environ['PASS_DB']
NAME_DB=os.environ['NAME_DB']
PORT_DB=os.environ['PORT_DB']

metadata = MetaData()

inetnavcx15_reps_test = Table('inetnavcx15_reps_test', metadata,
Column('id', Integer, primary_key=True),
Column('fechahora', DateTime),
Column('oficina', String(50)),
Column('source', String(50)),
Column('destination', String(50)),
Column('userid', String(50)),
Column('application', String(50)),
Column('sourceip', String(50)),
Column('destinationip', String(50)),
Column('appcategory', String(50)),
Column('appcontainer', String(50)),
Column('appsubcategory', String(50)),
Column('apptechnology', String(50)),
Column('category', String(50)),
Column('risk', String(50)),
Column('action', String(50)),
Column('destinationcountry', String(50)),
Column('destinationport', String(50)),
Column('outboundinterface', String(50)),
Column('bytes', String(50)),
Column('bytesreceived', String(50)),
Column('bytessent', String(50)),
Column('urls', String(50)),
Column('content', String(50)),
Column('threats', String(50)),
Column('sessions', String(50)),
Column('filetransfers', String(50)),
Column('datapatternmatches', String(50)))

inetnavcx15_new_test = Table('inetnavcx15_new_test', metadata,
Column('id', Integer, primary_key=True),
Column('fechahora', DateTime),
Column('oficina', String(50)),
Column('source', String(50)),
Column('destination', String(50)),
Column('userid', String(50)),
Column('application', String(50)),
Column('sourceip', String(50)),
Column('destinationip', String(50)),
Column('appcategory', String(50)),
Column('appcontainer', String(50)),
Column('appsubcategory', String(50)),
Column('apptechnology', String(50)),
Column('category', String(50)),
Column('risk', String(50)),
Column('action', String(50)),
Column('destinationcountry', String(50)),
Column('destinationport', String(50)),
Column('outboundinterface', String(50)),
Column('bytes', String(50)),
Column('bytesreceived', String(50)),
Column('bytessent', String(50)),
Column('urls', String(50)),
Column('content', String(50)),
Column('threats', String(50)),
Column('sessions', String(50)),
Column('filetransfers', String(50)),
Column('datapatternmatches', String(50)))

def executejob(fw_ip,report_name):
    CMD_GENERATE_REPORT='wget --no-check-certificate -qO- --no-proxy  "https://{}/api/?type=report&async=yes&reporttype=custom&reportname={}&key={}"'.format(fw_ip,report_name,PA_KEY)
    stdout = subprocess.check_output(CMD_GENERATE_REPORT,shell=True)
    soup=BeautifulSoup(stdout,"html.parser")
    tagdeclaration=soup.find('job')
    jobid=tagdeclaration.contents
    return jobid[0]


def bringreport(fw_ip,jobid):
    CMD_EXPORT_REPORT='wget --no-check-certificate -qO- --no-proxy  "https://{}/api/?type=report&async=yes&reporttype=dynamic&reportname=top-data-src-summary&key={}&action=get&job-id={}"'.format(fw_ip,PA_KEY,jobid)
    report = subprocess.check_output(CMD_EXPORT_REPORT,shell=True)
    return report

def saveXML(report):
    ts=time.time()
    TIMESTAMP=datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d_%H:%M:%S')
    FILENAME=TIMESTAMP+'_fwip.xml'
    print FILENAME
    f =  open(FILENAME, "wb")
    f.write(report)
    f.close
    return FILENAME

def parse_report(report,office):
    ts=time.time()
    TIMESTAMP=datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    soup=BeautifulSoup(report,"html.parser")
    i=1
    reporte=[]
    for block in soup.find_all("entry"):
        linea=[]
        linea.append(TIMESTAMP)
        linea.append(office)

        for line in block:
            if 'entry' in line:
                continue
            else:
                linea_temp=str(line.string).replace('\n','')
                if linea_temp != '':
                    linea.append(linea_temp)

        print linea
        if len(linea) >=28:
            print linea
            reporte.append(linea)
    print "Longitud reporte: {}".format(len(reporte))
    return reporte


def connect_db():
    engine = create_engine("mysql+pymysql://{}:{}@{}:{}".format(USER_DB,PASS_DB,NAME_DB,PORT_DB))
    conn = engine.connect()
    return conn


def insert_db(connection,report,window):
    connection.execute ("USE metricas")
    if window=='ALL':
       connection.execute (inetnavcx15_new_test.insert(),[{"fechahora":entrada[0],"oficina":entrada[1],"source":entrada[2],"destination":entrada[3],"userid":entrada[4],"application":entrada[5],"sourceip":entrada[6],"destinationip":entrada[8],"appcategory":entrada[10],"appcontainer":entrada[11],"appsubcategory":entrada[12],"apptechnology":entrada[13],"category":entrada[14],"risk":entrada[15],"action":entrada[16],"destinationcountry":entrada[17],"destinationport":entrada[18],"outboundinterface":entrada[19],"bytes":entrada[20],"bytesreceived":entrada[21],"bytessent":entrada[22],"urls":entrada[23],"content":entrada[24],"threats":entrada[25],"sessions":entrada[26],"filetransfers":entrada[27],"datapatternmatches":entrada[28]}for entrada in report])
    else:
        connection.execute (inetnavcx15_reps_test.insert(),[{"fechahora":entrada[0],"oficina":entrada[1],"source":entrada[2],"destination":entrada[3],"userid":entrada[4],"application":entrada[5],"sourceip":entrada[6],"destinationip":entrada[8],"appcategory":entrada[10],"appcontainer":entrada[11],"appsubcategory":entrada[12],"apptechnology":entrada[13],"category":entrada[14],"risk":entrada[15],"action":entrada[16],"destinationcountry":entrada[17],"destinationport":entrada[18],"outboundinterface":entrada[19],"bytes":entrada[20],"bytesreceived":entrada[21],"bytessent":entrada[22],"urls":entrada[23],"content":entrada[24],"threats":entrada[25],"sessions":entrada[26],"filetransfers":entrada[27],"datapatternmatches":entrada[28]}for entrada in report])
    #connection.close()


def testconnection(fwip):
    s=socket.socket()
    s.settimeout(3)
    try:
          s.connect((fwip,443))
    except Exception, e:
          return False
    else:
          return True
    finally:
          s.close()

def main():
    conbd=connect_db()
    Firewall_list = [i.split(",") for i in os.environ.get("FW").split(" ")]
    for firewall in Firewall_list:
        print firewall[0], firewall[1]
        if testconnection(firewall[0]):
           #INSERCION DATABASE REPS
           jobnumber=executejob(firewall[0],'all_traffic_reps')
           time.sleep(10)
           output_report=bringreport(firewall[0],jobnumber)
           reporte=parse_report(output_report,firewall[1])
           insert_db(conbd,reporte,'REPS')
           #INSERCION DATABASE GENERICA
           jobnumber=executejob(firewall[0],'all_traffic')
           time.sleep(10)
           output_report=bringreport(firewall[0],jobnumber)
           reporte=parse_report(output_report,firewall[1])
           insert_db(conbd,reporte,'ALL')

    conbd.close()

main()
