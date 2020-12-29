#!/usr/bin/python
##
#
##



















from socket import *
from sys import argv
import base64
import struct

host, port =('',80)
s=socket()
s.bind((host,port))
s.listen(5)
c,addr=s.accept()
data=c.recv(4086)
r=''
while data:
  r=r+data

  ligne=r.splitlines()

  rebDNS=base64.b64decode(ligne[0].split(' ')[1].split('?dns=')[1])

  def tupletostring(t):
    s=""
    for c in t:
      s=s+c
    return s
  def getname(string,pos):
    p=pos
    save=0
    name=""
    l=1
    if l==0:
      return p+1,""
    while l:
      l=struct.unpack("B",string[p])[0]
      if l>=192:
        #compression du message : les 2 premiers octets sont les 2 bits 11 puis le decalage depuis le debut de l'ID sur 14 bits
        if save == 0:
          save=p
        p=(l-192)*256+(struct.unpack("B",string[p+1])[0])
        l=struct.unpack("B",string[p])[0]
      if len(name) and l:
        name=name+'.'
      p=p+1
      name=name+tupletostring(struct.unpack("c"*l,string[p:(p+l)]))
      p=p+l
    if save > 0:
      p=save+2
    return p,name
  def retrquest(string,pos):
    p=pos
    p,name=getname(string,p)
    typ = struct.unpack(">H",string[p:p+2])[0]
    p=p+2
    clas = struct.unpack(">H",string[p:p+2])[0]
    p=p+2
    return p,name,typ,clas

  def typenumber(typ):
    if typ=='A':
      return 1
    if typ=='MX':
      return 15
    if typ=='NS':
      return 2
    if typ=='SOA':
      return 6

  def dnsrequete(name, typ):
    data=""
    #id sur 2 octets
    data=data+struct.pack(">H",0)
    # octet suivant : Recursion Desired
    data=data+"\\x81"+"\\x80"
    #octet suivant : 1
    #QDCOUNT sur 2 octets
    data=data+struct.pack(">H",1)
    data=data+struct.pack(">H",0)
    data=data+struct.pack(">H",0)
    data=data+struct.pack(">H",0)
    splitname=name.split('.')
    for c in splitname:
      data=data+struct.pack("B",len(c))
      for l in c:
         data=data+struct.pack("c",l)
    data=data+struct.pack("B",0)
    #TYPE
    data=data+struct.pack(">H",typenumber(typ))
    #CLASS 1 (IN) par defaut
    data=data+struct.pack(">H",1)
    return data

  def reponsedns(name,type):
    re=""
    f=open("../etc/bind/db.static",'r')
    for u  in f:
      re=""
      pL=u
      k=' '.join((pL).split())
      ligne= k.split(' ')
      if name == ligne[0] and type == ligne[2] and type != "MX":
        re+=struct.pack(">B",192)
        re+=struct.pack(">B",12)
        re+=struct.pack(">H",typenumber(type))
        re+=struct.pack(">H",1)
        re+=struct.pack(">H",0)
        re+=struct.pack(">H",0)
        part=ligne[3].split('.')
        re=re+struct.pack("B",len(part))
        for l in part:
          re=re+struct.pack("B",int(l))
        return re
      elif name == ligne[0] and type == ligne[2] and type == "MX" :
        re+=struct.pack(">H",0)
        re+=struct.pack(">H",typenumber(type))
        re+=struct.pack(">H",1)
        re+=struct.pack(">H",0)
        re+=struct.pack(">H",0)
        part=ligne[4].split('.')
        re=re+struct.pack("B",len(part))
        for l in part:
          re=re+struct.pack("B",int(l))
        return re

      else:
        return None
  def numbertotype(typ):
    if typ==1:
      return 'A'
    if typ==15:
      return 'MX'
    if typ==2:
      return 'NS'
    if typ==6:
      return 'SOA'
    return 'type inconnu'
  pos,name,typ,clas=retrquest(rebDNS,12)
  re=reponsedns(str(name),numbertotype(typ))
  final=dnsrequete( str(name) , numbertotype(typ))+str(re)
  print repr(final)




  def findaddrserver():
    resolvconf = open("/etc/resolv.conf", "r")
    lines = resolvconf.readlines()
    i=0
    while lines[i].split()[0]<>'nameserver':
      i=i+1
    server = lines[i].split()[1]
    resolvconf.close()
    return (server,53)
  answer=""
  if re==None:

    RebbSocket=socket(AF_INET,SOCK_DGRAM)
    RebbSocket.sendto(rebDNS,(findaddrserver()))
    answer=RebbSocket.recv(4096)
    RebbSocket.close()

  else:
    answer=final

  clientAnswer="""HTTP/1.0 200 OK\nContent-Type: application/dns-message\nContent-Length: %s\n\n%s""" %(str(len(answer)),answer)
  print repr(clientAnswer)
  c.send(clientAnswer)
  data=''



c.close()
s.close()
