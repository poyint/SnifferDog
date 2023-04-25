from PyQt5.QtWidgets import QApplication
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.uic import loadUiType

from os import path 
from Window2 import SecondWindow
import sys 


FORM_CLASS,_=loadUiType(path.join(path.dirname(__file__),"Design1.ui"))

class FirstWindow(QMainWindow, FORM_CLASS):

    def __init__(self,parent=None):
        super(FirstWindow,self).__init__(parent)
        QMainWindow.__init__(self)
        self.setupUi(self)
        self.Handle_ui()
        self.show()


    def Handle_ui(self):
        self.setWindowTitle("SNIFFER DOG")



    @classmethod
    def Q_App(cls):
        return QApplication(sys.argv)
        
