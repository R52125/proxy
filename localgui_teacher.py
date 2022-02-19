import datetime
import humanfriendly
import logging
import os
import signal
import sys
import traceback
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtNetwork import *
from PyQt5.QtWidgets import *
from PyQt5.QtWebSockets import *

class Window(QDialog):
    def __init__(self, parent=None):
        QDialog.__init__(self, parent, Qt.WindowMinMaxButtonsHint|Qt.WindowCloseButtonHint)

        self.setWindowTitle('LocalGUI')

        self.listenHostLine = QLineEdit('127.0.0.1')
        self.listenPortLine = QLineEdit('1081')
        self.listenPortLine.setPlaceholderText('1025~65535')

        self.remoteHostLine = QLineEdit('127.0.0.1')
        self.remotePortLine = QLineEdit('1082')
        self.remotePortLine.setPlaceholderText('1025~65535')

        self.usernameLine = QLineEdit('u1')
        self.passwordLine = QLineEdit('11')
        self.passwordLine.setEchoMode(QLineEdit.Password)

        self.consolePortLine = QLineEdit('1083')

        self.startBtn = QPushButton('Start')
        self.startBtn.clicked.connect(self.startClicked)

        selfProcessIdLine = QLabel(str(os.getpid()))
        
        self.processIdLine = QLabel()

        self.sendBandwidthLine = QLabel()
        self.recvBandwidthLine = QLabel()

        formLayout = QFormLayout()
        formLayout.addRow(QLabel('Listen Host:'), self.listenHostLine)
        formLayout.addRow(QLabel('Listen Port:'), self.listenPortLine)
        formLayout.addRow(QLabel('Remote Host:'), self.remoteHostLine)
        formLayout.addRow(QLabel('Remote Port:'), self.remotePortLine)
        formLayout.addRow(QLabel('Username:'), self.usernameLine)
        formLayout.addRow(QLabel('Password:'), self.passwordLine)
        formLayout.addRow(QLabel('Console Port:'), self.consolePortLine)
        formLayout.addRow(QLabel(''), self.startBtn)
        formLayout.addRow(QLabel('Self Process ID:'), selfProcessIdLine)
        formLayout.addRow(QLabel('Proxy Process ID:'), self.processIdLine)
        formLayout.addRow(QLabel('Send Bandwidth:'), self.sendBandwidthLine)
        formLayout.addRow(QLabel('Recv Bandwidth:'), self.recvBandwidthLine)

        self.setLayout(formLayout)
        self.resize(300, 600)

        self.process = QProcess()
        self.process.setProcessChannelMode(QProcess.MergedChannels)
        self.process.bytesWritten.connect(self.processBytesWritten)
        self.process.errorOccurred.connect(self.processErrorOccurred)
        self.process.finished.connect(self.processFinished)
        self.process.started.connect(self.processStarted)
        self.process.stateChanged.connect(self.processStateChanged)
        self.process.readyReadStandardOutput.connect(self.processReadyRead)

    def processBytesWritten(self, byteCount):
        log.debug(f'bytes={byteCount}')
    
    def processErrorOccurred(self, error):
        log.debug(f'err={error}')

    def processFinished(self):
        process = self.sender()
        log.debug(f'pid={process.processId()}')
        self.startBtn.setText('Start')
        self.processIdLine.setText('')

    def processReadyRead(self):
        data = self.process.readAll()
        try:
            msg = data.data().decode().strip()
            log.debug(f'msg={msg}')
        except Exception as exc:
            log.error(f'{traceback.format_exc()}')
            exit(1)

    def processStarted(self):
        process = self.sender()
        processId = process.processId()
        log.debug(f'pid={processId}')
        self.startBtn.setText('Stop')
        self.processIdLine.setText(str(processId))

        self.websocket = QWebSocket()
        self.websocket.connected.connect(self.websocketConnected)
        self.websocket.disconnected.connect(self.websocketDisconnected)
        self.websocket.textMessageReceived.connect(self.websocketMsgRcvd)
        self.websocket.open(QUrl(f'ws://127.0.0.1:{self.consolePortLine.text()}/'))

    def processStateChanged(self):
        process = self.sender()
        log.debug(f'pid={process.processId()} state={process.state()}')

    def startClicked(self):
        btn = self.sender()
        text = btn.text().lower()
        if text.startswith('start'):
            listenPort = self.listenPortLine.text()
            username = self.usernameLine.text()
            password = self.passwordLine.text()
            consolePort = self.consolePortLine.text()
            remoteHost = self.remoteHostLine.text()
            remotePort = self.remotePortLine.text()
            pythonExec = os.path.basename(sys.executable)
            cmdLine = f'{pythonExec} work6.py local -p {listenPort} -u {username} -w {password} -k {consolePort} {remoteHost} {remotePort}'
            log.debug(f'cmd={cmdLine}')
            self.process.start(cmdLine)
        else:
            self.process.kill()

    def websocketConnected(self):
        self.websocket.sendTextMessage('secret')

    def websocketDisconnected(self):
        self.process.kill()

    def websocketMsgRcvd(self, msg):
        log.debug(f'msg={msg}')
        sendBandwidth, recvBandwidth, *_ = msg.split()
        nowTime = QDateTime.currentDateTime().toString('hh:mm:ss')
        self.sendBandwidthLine.setText(f'{nowTime} {humanfriendly.format_size(int(sendBandwidth))}')
        self.recvBandwidthLine.setText(f'{nowTime} {humanfriendly.format_size(int(recvBandwidth))}')

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal.SIG_DFL)
 
    logFmt = logging.Formatter('%(asctime)s %(lineno)-3d %(levelname)7s %(funcName)-26s %(message)s')
    consoleHandler = logging.StreamHandler()
    consoleHandler.setLevel(logging.DEBUG)
    consoleHandler.setFormatter(logFmt)
    log = logging.getLogger(__file__)
    log.addHandler(consoleHandler)
    log.setLevel(logging.DEBUG)

    app = QApplication(sys.argv)
    # app.setQuitOnLastWindowClosed(False)
    app.setStyle('Windows')
    win = Window()
    win.show()
    sys.exit(app.exec_())
