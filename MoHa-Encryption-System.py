#-*- coding:UTF-8 -*-
import os
import sys
import wx
import md5
import _sha
import _sha256
import _sha512
import pyDes
import Crypto
import rsa
import binascii

class MyFrame(wx.Frame):
    def __init__(self):
        wx.Frame.__init__(self, None, -1, u"MoHa-Encryption-System（魔鉿加密系统）", size = (850, 700))
        panel = wx.Panel(self, -1)
        wx.StaticText(panel, -1, u"请输入需要加密的字符串:", pos = (10, 12))
        wx.StaticText(panel, -1, u"请输入需要加密的文件路径（该版本仅支持MD5与SHA系列消息摘要生成）:", pos = (10, 42))
        wx.StaticText(panel, -1, "MD5:", pos = (10, 92))
        wx.StaticText(panel, -1, "SHA-1:", pos = (10, 122))
        wx.StaticText(panel, -1, "SHA-224:", pos = (10, 152))
        wx.StaticText(panel, -1, "SHA-256:", pos = (10, 182))
        wx.StaticText(panel, -1, "SHA-384:", pos = (10, 212))
        wx.StaticText(panel, -1, "SHA-512:", pos = (10, 242))
        wx.StaticText(panel, -1, u"请输入由英文和数字组成的8位字符串作为DES加密密钥:", pos = (10, 282))
        wx.StaticText(panel, -1, u"输出DES密文:", pos = (10, 312))
        wx.StaticText(panel, -1, u"请输入DES密文:", pos = (10, 352))
        wx.StaticText(panel, -1, u"请输入由英文和数字组成的8位字符串作为密文解密密钥:", pos = (10, 382))
        wx.StaticText(panel, -1, u"输出原文:", pos = (10, 412))
        wx.StaticText(panel, -1, u"密钥（.pem格式文件）路径:", pos = (10, 482))
        wx.StaticText(panel, -1, u"当密钥路径为公钥路径时，使用公钥加密，获得密文:", pos = (10, 512))
        wx.StaticText(panel, -1, u"请输入RSA加密后的密文:", pos = (10, 542))
        wx.StaticText(panel, -1, u"当密钥路径为私钥路径时，使用私钥解密，获得原文:", pos = (10, 572))
        self.buttonCheckD = wx.Button(parent=panel, label=u"浏览", pos = (710,35))
        self.Bind(wx.EVT_BUTTON, self.OnButtonCheckD, self.buttonCheckD)
        self.buttonCheck1 = wx.Button(parent=panel, label=u"字符串加密", pos = (710,85))
        self.Bind(wx.EVT_BUTTON, self.OnButtonCheck1, self.buttonCheck1)
        self.buttonCheckED = wx.Button(parent=panel, label=u"文件加密", pos = (710,115))
        self.Bind(wx.EVT_BUTTON, self.OnButtonCheckED, self.buttonCheckED)
        self.inputN = wx.TextCtrl(panel, 1, u"开始魔铪！", pos = (200, 10),size=(500,20))
        self.inputD = wx.TextCtrl(panel, 1, "", pos = (420, 40),size=(280,20))
        self.Md5 = wx.TextCtrl(panel, 2, "", pos = (100, 90),size=(600,20))
        self.sha1 = wx.TextCtrl(panel, 3, "", pos = (100, 120),size=(600,20))
        self.sha224 = wx.TextCtrl(panel, 4, "", pos = (100, 150),size=(600,20))
        self.sha256 = wx.TextCtrl(panel, 5, "", pos = (100, 180),size=(600,20))
        self.sha384 = wx.TextCtrl(panel, 6, "", pos = (100, 210),size=(600,20))
        self.sha512 = wx.TextCtrl(panel, 7, "", pos = (100, 240),size=(600,20))
        self.DesKey1 = wx.TextCtrl(panel, 8, "", pos = (320, 280),size=(500,20))
        self.DesEncryption = wx.TextCtrl(panel, 9, "", pos = (100, 312),size=(600,20))
        self.buttonCheck2 = wx.Button(parent=panel, label=u"DES密钥加密", pos = (730,305))
        self.Bind(wx.EVT_BUTTON, self.OnButtonCheck2, self.buttonCheck2)
        self.DesSource = wx.TextCtrl(panel, 10, "", pos = (100, 352),size=(720,20))
        self.DesKey2 = wx.TextCtrl(panel, 11, "", pos = (320, 382),size=(500,20))
        self.DesDecryption = wx.TextCtrl(panel, 12, "", pos = (100, 412),size=(600,20))
        self.buttonCheck3 = wx.Button(parent=panel, label=u"DES密钥解密", pos = (730,405))
        self.Bind(wx.EVT_BUTTON, self.OnButtonCheck3, self.buttonCheck3)
        self.Dlg = wx.TextCtrl(panel, 13, "", pos = (180, 482),size=(530,20))
        self.CreatePem = wx.Button(parent=panel, label=u"先后生成公钥与私钥（.pem文件)，起名并选择保存目录", pos = (50,445))
        self.Bind(wx.EVT_BUTTON, self.SavePemFile, self.CreatePem)
        self.buttonCheck4 = wx.Button(parent=panel, label=u"浏览", pos = (730,475))
        self.Bind(wx.EVT_BUTTON, self.OpenFile, self.buttonCheck4)
        self.RsaEncode = wx.TextCtrl(panel, 14, "", pos = (300, 512),size=(410,20))
        self.buttonCheck5 = wx.Button(parent=panel, label=u"RSA加密", pos = (730,505))
        self.Bind(wx.EVT_BUTTON, self.ENCODE, self.buttonCheck5)
        self.RsaCode = wx.TextCtrl(panel, 15, "", pos = (180, 542),size=(530,20))
        self.RsaDecode = wx.TextCtrl(panel, 15, "", pos = (300, 572),size=(410,20))
        self.buttonCheck6 = wx.Button(parent=panel, label=u"RSA解密", pos = (730,565))
        self.Bind(wx.EVT_BUTTON, self.DECODE, self.buttonCheck6)

    def OnButtonCheck1(self, event):
        src = str(self.inputN.GetValue().encode('utf8'))
        m1 = md5.new()   
        m1.update(src)
        self.Md5.SetValue(m1.hexdigest().decode('utf8'))
        
        m2 = _sha.new()   
        m2.update(src)   
        self.sha1.SetValue(m2.hexdigest().decode('utf8'))
        
        m3 = _sha256.sha224()
        m3.update(src)   
        self.sha224.SetValue(m3.hexdigest().decode('utf8'))
        
        m4 = _sha256.sha256()
        m4.update(src)   
        self.sha256.SetValue(m4.hexdigest().decode('utf8'))
        
        m5 = _sha512.sha384()
        m5.update(src) 
        self.sha384.SetValue(m5.hexdigest().decode('utf8'))  
        
        m6 = _sha512.sha512() 
        m6.update(src)   
        self.sha512.SetValue(m6.hexdigest().decode('utf8'))

    def OnButtonCheckED(self, event):
        c = 'utf8'
        dlg = str(self.inputD.GetValue())
        with open(dlg,'rb') as EDfile:
            p = EDfile.read()
        src = str(p)
        m1 = md5.new()   
        m1.update(src)
        self.Md5.SetValue(m1.hexdigest().decode(c))
        
        m2 = _sha.new()   
        m2.update(src)   
        self.sha1.SetValue(m2.hexdigest().decode(c))
        
        m3 = _sha256.sha224()
        m3.update(src)   
        self.sha224.SetValue(m3.hexdigest().decode(c))
        
        m4 = _sha256.sha256()
        m4.update(src)   
        self.sha256.SetValue(m4.hexdigest().decode(c))
        
        m5 = _sha512.sha384()
        m5.update(src) 
        self.sha384.SetValue(m5.hexdigest().decode(c))  
        
        m6 = _sha512.sha512() 
        m6.update(src)   
        self.sha512.SetValue(m6.hexdigest().decode(c))

    def OnButtonCheck2(self, event):
        srcEn = str(self.inputN.GetValue().encode('utf8'))
        DKey = str(self.DesKey1.GetValue().encode('utf8'))
        k = pyDes.des(DKey, pyDes.CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
        data = k.encrypt(srcEn)
        self.DesEncryption.SetValue(binascii.hexlify(data).decode('utf8'))

    def OnButtonCheck3(self, event):
        srcEn = str(self.DesSource.GetValue().encode('utf8'))
        DKey = str(self.DesKey2.GetValue().encode('utf8'))
        k = pyDes.des(DKey, pyDes.CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
        data = k.decrypt(binascii.unhexlify(srcEn))
        self.DesDecryption.SetValue(data.decode('utf8'))

    def OpenFile(self,event):
        dlg = wx.FileDialog(self,u"打开数字签名",os.getcwd(),wildcard = "PEM files(*.pem)|*.pem|All files(*.*)|*.*",style = wx.FD_OPEN | wx.FD_FILE_MUST_EXIST)
        if dlg.ShowModal() == wx.ID_CANCEL: 
            return
        input_stream = dlg.GetPath()
        self.Dlg.SetValue(input_stream)

    def SavePemFile(self,event):
        (pubkey,privkey) = rsa.newkeys(1024)
        pub = pubkey.save_pkcs1()
        pri = privkey.save_pkcs1()

        PubDlg1 = wx.FileDialog(self,u"保存公钥",os.getcwd(),".pem",wildcard = "PEM files(*.pem)|*.pem|All files(*.*)|*.*",style = wx.FD_SAVE)
        if PubDlg1.ShowModal() == wx.ID_CANCEL: 
            return
        input_stream1 = PubDlg1.GetPath()
        pubfile = open(input_stream1,'w+')
        pubfile.write(pub)
        pubfile.close()

        PubDlg2 = wx.FileDialog(self,u"保存私钥",os.getcwd(),".pem",wildcard = "PEM files(*.pem)|*.pem|All files(*.*)|*.*",style = wx.FD_SAVE)
        if PubDlg2.ShowModal() == wx.ID_CANCEL: 
            return
        input_stream2 = PubDlg2.GetPath()
        prifile = open(input_stream2,'w+')
        prifile.write(pri)
        prifile.close()

    def ENCODE(self,event):
        src = str(self.inputN.GetValue().encode('utf8'))
        dlg = str(self.Dlg.GetValue())
        with open(dlg) as publicfile:
            p = publicfile.read()
            pubkey = rsa.PublicKey.load_pkcs1(p)
        crypto = rsa.encrypt(src,pubkey)
        self.RsaEncode.SetValue(binascii.hexlify(crypto).decode('utf8'))

    def DECODE(self,event):
        src = str(self.RsaCode.GetValue().encode('utf8'))
        dlg = str(self.Dlg.GetValue())
        with open(dlg) as privatefile:
            p = privatefile.read()
            privkey = rsa.PrivateKey.load_pkcs1(p)
        message = rsa.decrypt(binascii.unhexlify(src),privkey)
        self.RsaDecode.SetValue(message.decode('utf8'))

    def OnButtonCheckD(self,event):
        dlg = wx.FileDialog(self,u"打开需要加密的文件路径",os.getcwd(),style = wx.FD_OPEN | wx.FD_FILE_MUST_EXIST)
        if dlg.ShowModal() == wx.ID_CANCEL: 
            return
        input_stream = dlg.GetPath()
        self.inputD.SetValue(input_stream)

if __name__ == '__main__':
  app = wx.PySimpleApp()
  frame = MyFrame()
  frame.Show(True)
  app.MainLoop()
