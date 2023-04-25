from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.uic import loadUiType
from help import HelpWindow
from database import DATABASE
from scapy.all import *
from os import path 
import os
import sys 
from info import InfoWindow

FORM_CLASS,_=loadUiType(path.join(path.dirname(__file__),"Design2.ui"))

class SecondWindow(QMainWindow, FORM_CLASS):
    def __init__(self,parent=None):
        super(SecondWindow,self).__init__(parent)
        QMainWindow.__init__(self)
        self.setupUi(self)
        self.setWindowTitle("SNIFFER DOG")
        self.show()
        self.ui2 = InfoWindow()



    @classmethod
    def Q_App(cls):
        return QApplication(sys.argv)

        
    def add_packet(self,pac,color):
        items=[]
        item = QTreeWidgetItem(pac)
        for i in range(10):
            item.setBackground(i,QBrush(QColor(color)))
        items.append(item)
        self.PacketTable.insertTopLevelItems(0, items)
        return item


    def getFileName(self):
        file_filter ='Pcap file (*.pcap)'
        response=QFileDialog.getOpenFileName(
            parent=self,
            caption='select a pcap file',
            directory=os.getcwd(),
            filter=file_filter,
            initialFilter='Pcap file (*.pcap)'
        )
        return response[0]


    def file_save(self,list_text):
        name = QFileDialog.getSaveFileName(self, 'Save File')
        for text in list_text:
            wrpcap(name[0],text,append=True)


    def deleteItem(self,item):
        index=self.PacketTable.indexOfTopLevelItem(item)
        self.PacketTable.takeTopLevelItem(index)


    def get_text(self):
        data=DATABASE()
        text=self.textEdit.toPlainText()
        try:
            return data.filter(text)
        except Exception as e:
            print(e)

    def ask_to_save(self):
        buttonReply = QMessageBox.question(self, 'info', "Records may be lost. Do you want to save ?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if buttonReply == QMessageBox.Yes:
            return "Yes"
        else:
            return "No"
    
    def OpenHelp(self):
        self.window1 = QMainWindow()
        self.ui1 = HelpWindow()
        self.ui1.setupUi(self.window1)
        self.window1.setWindowTitle("Help")
        self.window1.show()

    def OpenInfo(self,text1,text2):
        self.window2 = QMainWindow()
        self.ui2.setupUi(self.window2)
        self.window2.setWindowTitle("Packet Details")
        self.packet_show(text1)
        self.packet_hex(text2)
        self.window2.show()
    def packet_show(self,text):
        self.ui2.Pshow.insertPlainText(text)
    def packet_hex(self,text):
        self.ui2.Phex.insertPlainText(text)
