"""
dcc.pyside
@author: ajacobs
8/14/2019
Helper functions for using PySide2 in Maya
"""

from PySide2 import (QtWidgets, QtCore, QtGui, QtUiTools)

import P4

from maya import OpenMayaUI as omui
from shiboken2 import wrapInstance

import sys


# convenience function to return an instance of the maya main window
def get_maya_main_window(type=QtWidgets.QWidget):
    maya_main_window_ptr = omui.MQtUtil.mainWindow()
    maya_main_window = wrapInstance(long(maya_main_window_ptr), type)
    return maya_main_window


# function to load .ui file from Qt Designer and return main window object
def load_ui(ui_file, parent=None):
    loader = QtUiTools.QUiLoader()
    ui_file_inst = QtCore.QFile(ui_file)
    ui_file_inst.open(QtCore.QFile.ReadOnly)
    ui = loader.load(ui_file_inst, parentWidget=parent)
    ui_file_inst.close()
    return ui


class DirLineEdit(QtWidgets.QLineEdit):
    ''' line edit that accepts directories '''

    def __init__(self):
        super(DirLineEdit, self).__init__()
        self.setDragEnabled(True)
        self.p4c = P4.P4()
        with self.p4c.connect():
            self.p4root = self.p4c.fetch_client()['Root']

    def keyPressEvent(self, event):
        ''' capture shift key to fix bug with losing focus in a QLineEdit when shift is pressed '''
        if event.key() in (QtCore.Qt.Key.Key_Shift, QtCore.Qt.Key.Key_Control):
            pass
        else:
            super(DirLineEdit, self).keyPressEvent(event)


class LineEdit(QtWidgets.QLineEdit):
    ''' line edit that avoids the shift key pressed bug '''

    def __init__(self):
        super(LineEdit, self).__init__()

    def keyPressEvent(self, event):
        ''' capture shift key to fix bug with losing focus in a QLineEdit when shift is pressed '''
        if event.key() in (QtCore.Qt.Key.Key_Shift, QtCore.Qt.Key.Key_Control):
            pass
        else:
            super(LineEdit, self).keyPressEvent(event)


class CustomTableModel(QtCore.QAbstractTableModel):
    def __init__(self, user_data=[[]], parent=None):
        QtCore.QAbstractTableModel.__init__(self)

        # List
        self.user_data = user_data
        self.setParent(parent)

    def headerData(self, section, orientation, role):
        if role == QtCore.Qt.DisplayRole:
            if orientation == QtCore.Qt.Horizontal:
                if section == 0:
                    self.parent().setColumnWidth(0, 250)
                    return 'Name'
                elif section == 1:
                    self.parent().setColumnWidth(1, 100)
                    return 'Start'
                elif section == 2:
                    self.parent().setColumnWidth(2, 100)
                    return 'End'

            if orientation == QtCore.Qt.Vertical:
                self.parent().setRowHeight(section, 20)
                return section

    def rowCount(self, parent):
        """
        Set row counts
        :param args:
        :param kwargs:
        :return:
        """
        return len(self.user_data)

    def columnCount(self, parent):
        """
        Set column count
        :param args:
        :param kwargs:
        :return:
        """
        return len(self.user_data[0])

    def flags(self, index):
        return QtCore.Qt.ItemIsEditable | QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable

    def data(self, index, role):
        if role == QtCore.Qt.EditRole:
            row = index.row()
            column = index.column()
            return self.user_data[row][column]

        if role == QtCore.Qt.DisplayRole:
            row = index.row()
            column = index.column()
            return self.user_data[row][column]

    def setData(self, index, value, role=QtCore.Qt.EditRole):
        if role == QtCore.Qt.EditRole:
            row = index.row()
            column = index.column()
            self.user_data[row][column] = value
            self.dataChanged.emit(index, index)
            return True
        return False

    def get(self):
        """
        Returns user data.
        :return:
        """
        return self.user_data


class UI(QtWidgets.QTableView):
    def __init__(self):
        QtWidgets.QTableView.__init__(self)

        data = [
            ['test1', 1, 10],
            ['test2', 11, 20],
            ['test3', 3, 30],
            ['test4', 4, 40]
        ]

        self.setModel(CustomTableModel(data))