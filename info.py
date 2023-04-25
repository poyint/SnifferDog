from PyQt5.QtWidgets import QApplication
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.uic import loadUiType

from os import path 
import sys 


FORM_CLASS,_=loadUiType(path.join(path.dirname(__file__),"info.ui"))

class InfoWindow(QMainWindow, FORM_CLASS):

    def __init__(self,parent=None):
        super(InfoWindow,self).__init__(parent)
        QMainWindow.__init__(self)
        self.setupUi(self)
        self.setWindowTitle("Packet Details")

