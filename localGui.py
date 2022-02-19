# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'Gui.ui'
#
# Created by: PyQt5 UI code generator 5.15.1
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.

import sys
import logging
import os
import asyncio
import humanfriendly
import time
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import *
from PyQt5.QtNetwork import *
from PyQt5.QtWebSockets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *

#global gl_username
#global gl_password

# 主窗口
class Ui_Form_1(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(484, 390)
        self.Go = QtWidgets.QPushButton(Form)
        self.Go.setGeometry(QtCore.QRect(190, 170, 93, 28))
        self.Go.setObjectName("Go")
        self.Go.clicked.connect(self.enter)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        self.Go.setText(_translate("Form", "Welcome"))

    def enter(self):
        self.hide()
        self.s = My_second_Form()
        self.s.show()

# 一级界面
class Ui_Form_2(object):
    def setupUi(self, Form):
        #global gl_username
        #global gl_password
        Form.setObjectName("Form")
        Form.resize(615, 406)
        self.username_lable = QtWidgets.QLabel(Form)
        self.username_lable.setGeometry(QtCore.QRect(20, 120, 101, 21))
        self.username_lable.setObjectName("username_lable")
        self.input_username = QtWidgets.QLineEdit(Form)
        self.input_username.setGeometry(QtCore.QRect(110, 120, 113, 21))
        self.input_username.setText("")
        self.password_lable = QtWidgets.QLabel(Form)
        self.password_lable.setGeometry(QtCore.QRect(20, 180, 101, 20))
        self.password_lable.setObjectName("password_lable")
        self.input_password = QtWidgets.QLineEdit(Form)
        self.input_password.setGeometry(QtCore.QRect(110, 180, 113, 21))
        self.input_password.setObjectName("input_password")
        self.input_password.setEchoMode(QLineEdit.Password)
        self.show_text = QtWidgets.QTextBrowser(Form)
        self.show_text.setGeometry(QtCore.QRect(280, 80, 256, 192))
        self.show_text.setObjectName("show_text")
        self.go_btn = QtWidgets.QPushButton(Form)
        self.go_btn.setGeometry(QtCore.QRect(120, 300, 61, 28))
        self.go_btn.setObjectName("go_btn")
        self.exit_btn = QtWidgets.QPushButton(Form)
        self.exit_btn.setGeometry(QtCore.QRect(340, 300, 61, 28))
        self.exit_btn.setObjectName("exit_btn")

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

        self.go_btn.clicked.connect(self.show_msg)
        self.exit_btn.clicked.connect(self.Hide)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        self.username_lable.setText(_translate("Form", "Username"))
        self.password_lable.setText(_translate("Form", "Password"))
        self.go_btn.setText(_translate("Form", "登录"))
        self.exit_btn.setText(_translate("Form", "退出"))

    # 显示欢迎信息
    def show_msg(self):
        self.username = self.input_username.text()
        self.password = self.input_password.text()
        if self.username!='' and self.password!='':
            self.show_text.setText(f'Welcome, {self.username}')
            self.show_text.show()

            self.go_btn.setText('next')
            self.go_btn.clicked.connect(self.monitor)
        # 显示错误界面
        else:
            self.e = Error_Form()
            self.e.show()

    # 显示监控（图形化）
    def monitor(self):
        self.hide()
        self.m = My_third_Form()
        self.m.show()

    # 退出
    def Hide(self):
        self.hide()
        self.h = MyMainForm()
        self.h.show()

# 二级界面
class Ui_Form_3(Ui_Form_2):    
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(762, 529)
        self.scrollArea = QtWidgets.QScrollArea(Form)
        self.scrollArea.setGeometry(QtCore.QRect(99, 76, 561, 341))
        self.scrollArea.setWidgetResizable(True)
        self.scrollArea.setObjectName("scrollArea")
        self.scrollAreaWidgetContents = QtWidgets.QWidget()
        self.scrollAreaWidgetContents.setGeometry(QtCore.QRect(0, 0, 559, 339))
        self.scrollAreaWidgetContents.setObjectName("scrollAreaWidgetContents")
        self.tableWidget = QtWidgets.QTableWidget(self.scrollAreaWidgetContents)
        self.tableWidget.setGeometry(QtCore.QRect(0, 0, 561, 341))
        self.tableWidget.setColumnCount(4)
        self.tableWidget.setObjectName("tableWidget")
        self.tableWidget.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(3, item)
        self.scrollArea.setWidget(self.scrollAreaWidgetContents)
        self.Start_btn = QtWidgets.QPushButton(Form)
        self.Start_btn.setGeometry(QtCore.QRect(160, 430, 93, 28))
        self.Start_btn.setObjectName("Start_btn")
        self.Stop_btn = QtWidgets.QPushButton(Form)
        self.Stop_btn.setGeometry(QtCore.QRect(480, 430, 93, 28))
        self.Stop_btn.setObjectName("Stop_btn")
        self.Exit_btn = QtWidgets.QPushButton(Form)
        self.Exit_btn.setGeometry(QtCore.QRect(310, 480, 93, 28))
        self.Exit_btn.setObjectName("Exit_btn")
        self.Host_label = QtWidgets.QLabel(Form)
        self.Host_label.setGeometry(QtCore.QRect(410, 20, 71, 21))
        self.Host_label.setObjectName("Host_label")
        self.ConsolePort_lable = QtWidgets.QLabel(Form)
        self.ConsolePort_lable.setGeometry(QtCore.QRect(410, 50, 91, 21))
        self.ConsolePort_lable.setObjectName("ConsolePort_lable")
        self.Host_text = QtWidgets.QLineEdit(Form)
        self.Host_text.setGeometry(QtCore.QRect(500, 20, 141, 21))
        self.Host_text.setText("")
        self.Host_text.setObjectName("Host_text")
        self.ConsolePort_text = QtWidgets.QLineEdit(Form)
        self.ConsolePort_text.setGeometry(QtCore.QRect(500, 50, 131, 21))
        self.ConsolePort_text.setObjectName("ConsolePort_text")
        self.username_lable = QtWidgets.QLabel(Form)
        self.username_lable.setGeometry(QtCore.QRect(100, 20, 72, 21))
        self.username_lable.setObjectName("username_lable")
        self.label = QtWidgets.QLabel(Form)
        self.label.setGeometry(QtCore.QRect(100, 50, 72, 21))
        self.label.setObjectName("label")
        self.username_text = QtWidgets.QLineEdit(Form)
        self.username_text.setGeometry(QtCore.QRect(170, 20, 151, 21))
        self.username_text.setObjectName("username_text")
        self.password_text = QtWidgets.QLineEdit(Form)
        self.password_text.setGeometry(QtCore.QRect(170, 50, 151, 21))
        self.password_text.setObjectName("password_text")
        self.password_text.setEchoMode(QLineEdit.Password)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

        self.Stop_btn.clicked.connect(self.Stop)
        self.Start_btn.clicked.connect(self.Start)
        self.Exit_btn.clicked.connect(self.Hide)

        # -----使用QProcess类管理localProxy-----
        self.process = QProcess()
        self.process.setProcessChannelMode(QProcess.MergedChannels)
        #self.process.finished.connect(self.process_finished)
        self.process.started.connect(self.process_started)
        self.process.readyReadStandardOutput.connect(self.process_readyread)


    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        item = self.tableWidget.horizontalHeaderItem(0)
        item.setText(_translate("Form", "Time"))
        item = self.tableWidget.horizontalHeaderItem(1)
        item.setText(_translate("Form", "Connect or not"))
        item = self.tableWidget.horizontalHeaderItem(2)
        item.setText(_translate("Form", "SendBandWidth"))
        item = self.tableWidget.horizontalHeaderItem(3)
        item.setText(_translate("Form", "RecvBandWidth"))
        self.Start_btn.setText(_translate("Form", "Start"))
        self.Stop_btn.setText(_translate("Form", "Stop"))
        self.Exit_btn.setText(_translate("Form", "Exit"))
        self.Host_label.setText(_translate("Form", "Host"))
        self.ConsolePort_lable.setText(_translate("Form", "ConsolePort"))
        self.username_lable.setText(_translate("Form", "username"))
        self.label.setText(_translate("Form", "password"))

    # 开始监控
    def Start(self):
        self.host = self.Host_text.text()
        self.consolePort = self.ConsolePort_text.text()
        msg = Ui_Form_2()
        self.username = self.username_text.text()
        self.password = self.password_text.text()
        pythonExec = os.path.basename(sys.executable)
        
        cmdLine = f'{pythonExec} localproxy.py -u {self.username} -p {self.password} -c {self.consolePort}'
        logging.debug(f'cmd={cmdLine}')
        self.process.start(cmdLine)

    def process_readyread(self):
        data = self.process.readAll()
        #print(type(data))
        try:
            msg = data.data().decode().strip()
            logging.debug(f'msg={msg}')
        except Exception as exc:
            logging.error(f'{traceback.format_exc()}')
            exit(1)

    def process_started(self):
        # 等同于self.process，使用sender适应性更好
        process = self.sender()
        processId = process.processId()
        logging.basicConfig(filename='example.log', level=logging.DEBUG)
        logging.debug(f'pid={processId}')
        #self.processIdLine = QLineEdit()
        #self.processIdLine.setText(str(processId))

        self.websocket = QWebSocket()
        self.websocket.connected.connect(self.websocket_connected)
        self.websocket.disconnected.connect(self.websocket_disconnected)
        self.websocket.textMessageReceived.connect(self.websocket_message_rec)
        self.websocket.open(QUrl(f'ws://127.0.0.1:{self.ConsolePort_text.text()}/'))

    def websocket_connected(self):
        self.websocket.sendTextMessage('secret')
    
    def websocket_disconnected(self):
        self.process.kill()

    def websocket_message_rec(self, msg):
        logging.debug(f'msg={msg}')
        send_Bandwidth, recv_Bandwidth, *_ = msg.split()
        self.nowTime = QDateTime.currentDateTime().toString('hh:mm:ss')
        self.sendmsg_input = f'{humanfriendly.format_size(int(send_Bandwidth))}'
        self.recvmsg_input = f'{humanfriendly.format_size(int(recv_Bandwidth))}'
        row = self.tableWidget.rowCount()   # 返回当前行数
        self.tableWidget.insertRow(row)     # 尾部插入一行新行表格
        col = self.tableWidget.columnCount()# 返回当前列数
        self.tableWidget.setItem(row, 0, QTableWidgetItem(self.nowTime))
        self.tableWidget.setItem(row, 1, QTableWidgetItem('connect'))
        self.tableWidget.setItem(row, 2, QTableWidgetItem(self.sendmsg_input))
        self.tableWidget.setItem(row, 3, QTableWidgetItem(self.recvmsg_input))

    # 进程停止
    def Stop(self):
        self.process.kill()
        
    # 退出
    def Hide(self):
        self.hide()
        self.h = My_second_Form()
        self.h.show()

# 错误界面
class Error_Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(400, 124)
        self.error_lable = QtWidgets.QLabel(Form)
        self.error_lable.setGeometry(QtCore.QRect(60, 40, 291, 41))
        self.error_lable.setFrameShadow(QtWidgets.QFrame.Plain)
        self.error_lable.setObjectName("error_lable")

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        self.error_lable.setText(_translate("Form", "error: username or password is null"))

class MyMainForm(QMainWindow, Ui_Form_1):
    def __init__(self, parent=None):
        super(MyMainForm, self).__init__(parent)
        self.setupUi(self)

class My_second_Form(QDialog, Ui_Form_2):
    def __init__(self, parent=None):
        super(My_second_Form, self).__init__(parent)
        self.setupUi(self)

class My_third_Form(QDialog, Ui_Form_3):
    def __init__(self, parent=None):
        super(My_third_Form, self).__init__(parent)
        self.setupUi(self)

class Error_Form(QDialog, Error_Ui_Form):
    def __init__(self, parent=None):
        super(Error_Form, self).__init__(parent)
        self.setupUi(self)

def ui_main():
    app = QApplication(sys.argv)
    window = MyMainForm()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    ui_main()