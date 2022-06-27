"""
dcc.maya.validation.checker
@author: ajacobs
8/20/2019
Main functions for Maya checker
"""
import logging
import pymel.core as pmc
import os
import sys
import re
import importlib
import traceback
import time
import subprocess

log_level = logging.getLogger().getEffectiveLevel()

# resetting log level after pymel call in rig.tools
logging.getLogger().setLevel(log_level)


try:
    from PySide2.QtWidgets import (QDialog, QListWidgetItem, QVBoxLayout, QPushButton, QSplitter, QListWidget,
                                   QTextEdit, QMenu, QHBoxLayout, QCheckBox, QListView, QLabel, QFileDialog)

    from PySide2.QtCore import QAbstractListModel, QModelIndex, Qt
    from pyside import DirLineEdit
    from pyside import get_maya_main_window

    maya_main_window = get_maya_main_window()
except:
    maya_main_window = None


# directory look up table for departments
DEPT_LOOKUP = {'/testing/': 'testing'}

# dictionary of patterns to exclude files from department lookups
DEPT_EXCLUDE = {}


# custom exceptions for checker errors
class CheckerRuntimeException(Exception):
    """
    checker exception for errors in scan or repair functions
    """
    pass


class CheckerError(Exception):
    """
    error checker exception:
    takes a string message and can optionally accept a list of objects that generated the error
    """

    def __init__(self, msg, objects=None):
        super(CheckerError, self).__init__()
        self.msg = msg
        self.objects = objects


class CheckerWarning(Exception):
    """
    warning checker exception:
    takes a string message and can optionally accept a list of objects that generated the warning
    """

    def __init__(self, msg, objects=None):
        super(CheckerWarning, self).__init__()
        self.msg = msg
        self.objects = objects


class Checker:
    """
    main checker class that scans and repairs scenes
    """

    def __init__(self, dept=None, batch=False):
        # determine type of file and get corresponding modules
        self.modules = []
        self.dept = dept
        self.logger = logging.getLogger(__name__)
        self.excluded = []
        self.batch = batch

        self._errors = {}
        self._warnings = {}
        self._script_errors = []

        if not dept:
            self.dept = self.get_department(dept)
        self.modules = self.get_modules()

    @staticmethod
    def get_department(dept):
        """
        Tries to determine what department the file is located in so the right validation scripts can be run.
        :param dept:
        :return: department or errors out
        """
        scene_name = pmc.sceneName()

        for pattern in sorted(DEPT_LOOKUP.keys()):
            if re.search(pattern, scene_name, re.IGNORECASE) or dept == DEPT_LOOKUP[pattern]:
                temp_dept = DEPT_LOOKUP[pattern]

                # make sure file doesn't match pattern for files to exclude from department match
                if temp_dept in DEPT_EXCLUDE.keys():
                    if re.search(DEPT_EXCLUDE[temp_dept], scene_name, re.IGNORECASE):
                        continue

                dept = DEPT_LOOKUP[pattern]
                break

        # if department has not been set, thrown an error
        if not dept:
            raise Exception(
                'Unable to determine department. Please make sure your Maya file is in the correct directory.')
        return dept

    def get_modules(self):
        """
        Gets modules associated with a department
        :return: departments
        """

        def filter_modules(checker_files, dept):
            modules = []
            for checker_file in checker_files:
                # ignore init files
                if checker_file == '__init__.py':
                    continue
                if os.path.splitext(checker_file)[1] == '.py':
                    module_name = __name__.replace('.checker', '') + '.' + dept + '.' + \
                                  os.path.splitext(checker_file)[0]

                    # removes and module that may have been loaded previously
                    if module_name in sys.modules.keys():
                        del sys.modules[module_name]

                    modules.append(importlib.import_module(module_name))
            return modules

        curr_dir = os.path.dirname(__file__)
        func_dir = os.path.join(curr_dir, self.dept)

        if os.path.exists(func_dir):
            # get dept specific modules
            self.modules = filter_modules(os.listdir(func_dir), self.dept)

            # exclude shared modules from special checkers
            if self.dept not in DEPT_LOOKUP.values():
                return

            # add shared modules
            self.modules = self.modules + filter_modules(os.listdir(os.path.join(curr_dir, 'shared')), 'shared')

        return self.modules

    def filter_excluded(self, nodes):
        """
        filter list against nodes that are excluded from export
        """
        self.logger.debug('Excluded nodes:')
        self.logger.debug(self.excluded)
        filtered_nodes = []
        for node in nodes:
            # TODO: Add a filter here. None now as I do not know what filters are needed, if any.
            filtered_nodes.append(node)

        return filtered_nodes

    def scan(self):
        """scan using all of the modules found for the department"""
        # clear out errors and warnings before doing a new scan
        self._errors = {}
        self._warnings = {}
        scan_errors = []
        start = time.time()
        # refresh list of nodes to be excluded from scans
        # TODO: this is an excluded variable for the scan.
        self.excluded = None
        for module in self.modules:
            module_name = module.__name__
            try:
                self.logger.info('Running scan using... ' + module_name)
                module.scan()

            except CheckerError as e:
                if e.objects:
                    nodes = e.objects
                    # Add nodes to ignore for equipment to excluded
                    # Specific folder filters could be added with additional filter functions
                    if nodes:
                        nodes = self.filter_excluded(nodes)
                    if not nodes:
                        continue
                    else:
                        e.objects = nodes

                self.logger.info('  Error found using module: ' + module_name)
                self.logger.info('    - ' + e.msg + '\r\n')
                self._errors[module] = e

            except CheckerWarning as e:
                if e.objects:
                    nodes = e.objects
                    # Add nodes to ignore for equipment to excluded
                    # Specific folder filters could be added with additional filter functions
                    if nodes:
                        nodes = self.filter_excluded(nodes)
                    if not nodes:
                        continue
                    else:
                        e.objects = nodes

                self.logger.info('  Warning found using module: ' + module_name)
                self.logger.info('    - ' + e.msg + '\r\n')
                self._warnings[module] = e

            except Exception:
                # if there is an error while trying to run a scan, print it out, but continue scanning
                self.logger.error('Error while trying to run scan using module: ' + module_name, exc_info=True)
                scan_errors.append(module_name)

        self.logger.info('Scan completed in %s seconds' % (time.time() - start))

        if scan_errors:
            self.logger.error('Errors while trying to scan')
            # Logs the module that caused the error
            for errModule in scan_errors:
                self.logger.error('Module: %s' % errModule)
                self._script_errors.append(errModule)

            if self.batch:
                raise CheckerRuntimeException('Errors in scan functions')

    def repair_all(self):
        """ attempt to repair all errors if repair functions exist"""
        repair_errors = []
        for module in self._errors:
            module_name = module.__name__
            if 'repair' in dir(module):
                # Tries to repair all errors using the validation scripts repair function... if one exists
                try:
                    self.logger.info('Attempting repair using module: ' + module_name)
                    # check for any objects saved when scanning
                    objects = self._errors[module].objects
                    if objects:
                        module.repair(objects)
                    else:
                        module.repair()

                except Exception:
                    self.logger.error('Error in repair function: ' + module_name + '.repair()', exc_info=True)
                    repair_errors.append(module_name)

        for module in self._warnings:
            if 'repair' in dir(module):
                module_name = module.__name__
                try:
                    self.logger.info('Attempting repair using module: ' + module_name)
                    # check for any objects saved when scanning
                    objects = self._warnings[module].objects
                    if objects:
                        module.repair(objects)
                    else:
                        module.repair()
                except Exception:
                    self.logger.error('Error in repair function: ' + module_name + '.repair()', exc_info=True)
                    repair_errors.append(module_name)

        if repair_errors:
            error_string = 'Errors while trying to repair:\n'
            for err in repair_errors:
                error_string += err + '\n'
            raise CheckerRuntimeException(error_string)

    def get_errors(self):
        """ return errors """
        return self._errors

    def get_warnings(self):
        """ return warnings """
        return self._warnings

    def get_script_errors(self):
        """ return modules with script errors """
        return self._script_errors

    def has_errors(self):
        """ function to identify if errors were found """
        if self.get_errors():
            return True
        else:
            return False

    def has_warnings(self):
        """ function to identify if warnings were found """
        if self.get_warnings():
            return True
        else:
            return False

    def has_script_errors(self):
        """ function to identify if there were script errors in the scan """
        if self.get_script_errors():
            return True
        else:
            return False

    def show_ui(self):
        checker_ui = CheckerUI(self)
        checker_ui.show()


class CheckerSelectUI(QDialog):
    """ UI for checker object selection """

    def __init__(self, name, objects):
        super(CheckerSelectUI, self).__init__()
        if pmc.window('checkerSelectUI', exists=True):
            pmc.deleteUI('checkerSelectUI')
        self.setObjectName('checkerSelectUI')
        self.objects = objects
        self.name = name
        self.setParent(maya_main_window)
        self.setWindowFlags(Qt.Window)
        self.objects_model = CheckerObjectModel(self.objects)
        self.setWindowTitle('Object selector - %s' % self.name)

        # Setting up class variables for UI
        self.main_layout = QVBoxLayout()
        self.checkbox_layout = QHBoxLayout()
        self.objects_view = QListView()

        self.setup_ui()
        self.setMinimumSize(500, 300)

    def setup_ui(self):
        self.setLayout(self.main_layout)

        self.main_layout.addLayout(self.checkbox_layout)

        # object list view
        self.objects_view.setModel(self.objects_model)
        self.objects_view.clicked.connect(self.select_object)
        self.main_layout.addWidget(self.objects_view)

    def select_object(self):
        """
        Selects the object based on the index of the UI
        """
        index = self.objects_view.selectedIndexes()
        if not index:
            return
        index = index[0]

        pmc.select(self.objects_model.data(index, Qt.UserRole))


class CheckerObjectModel(QAbstractListModel):
    """ Model for checker object select list view """

    def __init__(self, objects):
        super(CheckerObjectModel, self).__init__()
        self.objects = objects
        self._full_path = True

    def rowCount(self, parent=QModelIndex()):
        return len(self.objects)

    def data(self, index, role=Qt.DisplayRole):
        # set display role. Should be using PyNodes
        if index.isValid() and role == Qt.DisplayRole:
            # test for pynode
            if 'pymel.core.nodetypes' in str(type(self.objects[index.row()])):
                return self.objects[index.row()].nodeName()
            else:
                self.objects[index.row()]

        elif index.isValid() and role == Qt.UserRole:
            return self.objects[index.row()]
        else:
            return

    def set_full_path(self, value):
        self._full_path = value


class CheckerUI(QDialog):
    """ GUI for handling errors from the checker"""

    def __init__(self, checker, scan=False):
        super(CheckerUI, self).__init__()
        self.checker = checker
        if pmc.window('checkerUI', exists=True):
            pmc.deleteUI('checkerUI')
        if pmc.window('checkerSelectUI', exists=True):
            pmc.deleteUI('checkerSelectUI')
        self.setObjectName('checkerUI')
        self.setParent(maya_main_window)
        self.setWindowFlags(Qt.Window)

        # Setting class variables for UI
        self.main_layout = QVBoxLayout()
        self.scan_button = QPushButton()
        self.splitter = QSplitter()
        self.list_widget = QListWidget()
        self.detail_field = QTextEdit()
        self.select_button = QPushButton()
        self.repair_button = QPushButton()

        self.setup_ui()
        # populate the list widget view the first time, assuming a scan has already been complete
        self.refresh_list(scan=scan)

    def setup_ui(self):
        if self.checker.dept == 'animations':
            dept = 'Animation'
        elif self.checker.dept == 'backgrounds':
            dept = 'Backgrounds'
        elif self.checker.dept == 'props':
            dept = 'Props'
        elif self.checker.dept == 'characters':
            dept = 'Characters'
        else:
            dept = None

        if not dept:
            self.setWindowTitle('Maya Checker')
        else:
            self.setWindowTitle('Maya Checker - ' + dept)

        # scan button
        self.scan_button.setText('Scan Scene')
        self.scan_button.clicked.connect(self.refresh_list)
        self.main_layout.addWidget(self.scan_button)
        self.main_layout.addSpacing(5)

        # splitter to allow for resizing of the list widget and description window
        self.splitter.setOrientation(Qt.Vertical)
        self.splitter.setChildrenCollapsible(False)
        self.main_layout.addWidget(self.splitter)

        # list widget
        self.list_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.list_widget.customContextMenuRequested.connect(self.context_menu)
        self.list_widget.itemSelectionChanged.connect(self.get_info)
        self.list_widget.itemSelectionChanged.connect(self.update_select_button)
        self.splitter.addWidget(self.list_widget)

        # detail text field
        self.detail_field.setReadOnly(True)
        self.splitter.addWidget(self.detail_field)

        # select objects button
        self.select_button.setText('Select Objects')
        self.select_button.setVisible(False)
        self.select_button.clicked.connect(self.select_objects_ui)
        self.main_layout.addWidget(self.select_button)

        # repair button
        self.repair_button.setText('Repair All Errors')
        self.repair_button.clicked.connect(self.repair_all)
        self.main_layout.addWidget(self.repair_button)

        self.setLayout(self.main_layout)
        self.setMinimumSize(400, 200)

    def refresh_list(self, scan=True):
        """ method to populate the list widget """
        self.list_widget.clear()

        if scan:
            self.checker.scan()
        errors = self.checker.get_errors()
        warnings = self.checker.get_warnings()

        if errors:
            for module in errors:
                list_item = CheckerListItem(module, errors[module], level=CheckerListItem.ERROR)
                self.list_widget.addItem(list_item)

        if warnings:
            for module in warnings:
                list_item = CheckerListItem(module, warnings[module], level=CheckerListItem.WARNING)
                self.list_widget.addItem(list_item)

        if not errors and not warnings and not self.checker.has_script_errors():
            self.detail_field.setText('No errors found.')

        elif self.checker.has_script_errors():
            error_string = 'Some checker scan functions had errors:\n'
            for module in self.checker.get_script_errors():
                error_string += module + '\n'
            self.detail_field.setText(error_string)

        else:
            self.detail_field.setText('')

    def repair_all(self):
        """  run all repair functions available """
        self.checker.repair_all()
        self.refresh_list()

    def repair_item(self):
        """ repair a single item in the list widget and refresh the list"""
        item = self.list_widget.selectedItems()[0]
        item.repair()
        self.refresh_list()

    def update_select_button(self):
        """ update the select object button when the list item changes """
        if self.list_widget.selectedItems():
            item = self.list_widget.selectedItems()[0]

        else:
            return

        if item.has_objects():
            self.select_button.setVisible(True)

        else:
            self.select_button.setVisible(False)

    def select_all_objects(self):
        """ menu action to select all objects associated with the errors """
        item = self.list_widget.selectedItems()[0]
        pmc.select(clear=True)
        objects = item.get_objects()
        for obj in objects:
            try:
                pmc.select(str(obj), add=True)
            except Exception:
                # if we can't find an object, catch the exception, but continue trying to select objects
                print('Unable to find object ' + obj)

    def select_objects_ui(self):
        """ launch UI to select individual objects """
        item = self.list_widget.selectedItems()[0]
        objects = item.get_objects()
        module_name = item.get_module_name()
        select_ui = CheckerSelectUI(module_name, objects)
        select_ui.show()

    def get_info(self):
        """ populate description field """
        if self.list_widget.selectedItems():
            item = self.list_widget.selectedItems()[0]
        else:
            self.detail_field.setText('')
            return
        if item.has_info():
            description = item.info()
            objects = item.get_objects()
            if objects:
                num_objects = len(objects)
                if num_objects == 1:
                    description += ('\n\n%s object affected:\n\n' % num_objects)
                else:
                    description += ('\n\n%s objects affected:\n\n' % num_objects)
                for obj in objects:
                    description += str(obj) + '\n'
        else:
            description = ''
        self.detail_field.setText(description)

    def context_menu(self, pos):
        """ context menu for list widget """
        item = self.list_widget.itemAt(pos)
        if item:
            # check for repair functions or objects passed to exception
            repair = item.has_repair()
            objects = item.has_objects()
            if not repair and not objects:
                return
            menu = QMenu()
            if repair:
                repair_menu_item = menu.addAction('Run Repair Function')
                repair_menu_item.triggered.connect(self.repair_item)
            if objects:
                obj_all_menu_item = menu.addAction('Select All Objects')
                obj_all_menu_item.triggered.connect(self.select_all_objects)
                obj_menu_item = menu.addAction('Select Objects...')
                obj_menu_item.triggered.connect(self.select_objects_ui)

            menu.exec_(self.list_widget.mapToGlobal(pos))


class CheckerListItem(QListWidgetItem):
    """ custom list widget item that contains information about the checker errors"""
    WARNING = 0
    ERROR = 1

    def __init__(self, module, exception, level):
        super(CheckerListItem, self).__init__()
        self.module = module
        self.exception = exception
        self.objects = exception.objects
        self.level = level
        if self.level == self.ERROR:
            self.message = 'Error: ' + self.exception.msg
        if self.level == self.WARNING:
            self.message = 'Warning: ' + self.exception.msg
        self.setText(self.message)
        self.infoMsg = None

    def repair(self):
        """ attempt repair using repair function if available """
        if self.has_repair():
            print('Attempting repair using module: ' + self.module.__name__)
            try:
                if self.has_objects():
                    self.module.repair(self.objects)
                else:
                    self.module.repair()
            except Exception:
                print(traceback.format_exc())
                raise CheckerRuntimeException('Error while running repair in module: ' + self.module.__name__)

    def info(self):
        """ return info string from module """
        if self.has_info():
            if self.infoMsg:
                return self.infoMsg
            if self.level == self.ERROR:
                self.infoMsg = 'Error: ' + self.module.info()
            if self.level == self.WARNING:
                self.infoMsg = 'Warning: ' + self.module.info()
            return self.infoMsg
        else:
            return ''

    def has_repair(self):
        """ returns True if the module has a repair function """
        if 'repair' in dir(self.module):
            return True
        else:
            return False

    def has_info(self):
        """ returns True if the module has an info function """
        if 'info' in dir(self.module):
            return True
        else:
            return False

    def get_objects(self):
        """ return all objects associated with the error """
        return self.objects

    def get_module_name(self):
        """ return scan module """
        return self.module.__name__

    def has_objects(self):
        """ returns True if there are objects associated with the error """
        if self.get_objects():
            return True
        else:
            return False


class CheckerBatchUI(QDialog):
    """ UI for batch checker operations """

    def __init__(self):
        super(CheckerBatchUI, self).__init__()
        self.logger = logging.getLogger(__name__)
        if pmc.window('checkerBatchUI', exists=True):
            pmc.deleteUI('checkerBatchUI')
        self.setObjectName('checkerBatchUI')
        self.setParent(maya_main_window)
        self.setWindowFlags(Qt.Window)
        self.setWindowTitle('Batch checker')

        # setting up class variables
        self.main_layout = QVBoxLayout()
        self.checkbox_layout = QHBoxLayout()
        self.recurse_checkbox = QCheckBox()
        self.warning_checkbox = QCheckBox()
        self.batch_checkbox = QCheckBox()
        self.verbose_checkbox = QCheckBox()
        self.dir_layout = QHBoxLayout()
        self.dir_line_edit = DirLineEdit()
        self.dir_button = QPushButton()
        self.regex_line_edit = DirLineEdit()
        self.button_layout = QHBoxLayout()
        self.ok_button = QPushButton()
        self.cancel_button = QPushButton()

        self.setup_ui()
        self.setMinimumSize(350, 100)

    def setup_ui(self):

        self.setLayout(self.main_layout)

        self.main_layout.addLayout(self.checkbox_layout)

        # recurse checkbox
        self.recurse_checkbox.setChecked(True)
        self.recurse_checkbox.setText('Include subdirectories')
        self.checkbox_layout.addWidget(self.recurse_checkbox)

        # warning checkbox
        self.warning_checkbox .setChecked(False)
        self.warning_checkbox .setText('Include warnings')
        self.checkbox_layout.addWidget(self.warning_checkbox)

        # batch mode checkbox
        self.batch_checkbox.setChecked(True)
        self.batch_checkbox.setText('Use mayabatch mode')
        self.checkbox_layout.addWidget(self.batch_checkbox)

        # verbose logging checkbox
        self.verbose_checkbox.setChecked(False)
        self.verbose_checkbox.setText('Verbose logging')
        self.checkbox_layout.addWidget(self.verbose_checkbox)

        self.checkbox_layout.addStretch()

        self.main_layout.addSpacing(10)

        # directory label
        dir_label = QLabel()
        dir_label.setText('Directory')
        self.main_layout.addWidget(dir_label)

        # directory layout
        self.main_layout.addLayout(self.dirLayout)

        # directory field
        self.dirLayout.addWidget(self.dir_line_edit)

        # directory browse button
        self.dir_button.setText('...')
        self.dir_button.clicked.connect(self.get_directory)
        self.dir_layout.addWidget(self.dirButton)

        # regex label
        regex_label = QLabel()
        regex_label.setText('Regex filter')
        self.main_layout.addWidget(regex_label)

        # regex field
        self.main_layout.addWidget(self.regex_line_edit)

        # button layout
        self.main_layout.addLayout(self.button_ayout)

        # OK button
        self.ok_button.setText('OK')
        self.ok_button.clicked.connect(self.run_batch_check)
        self.button_layout.addWidget(self.ok_button)

        # cancel button
        self.cancel_button.setText('Cancel')
        self.cancel_button.clicked.connect(self.close)
        self.button_layout.addWidget(self.cancel_button)

        self.main_layout.addStretch()

    def get_directory(self):
        """ get the directory and populate the text field """
        # TODO: adjust the dir to work with DCL
        dir_filter = os.path.join(os.environ['ART_ROOT'], 'Project', 'Project_Art')

        directory = QFileDialog.getExistingDirectory(parent=self, caption='Batch Checker Directory', dir=dir_filter)
        if directory and os.path.isdir(directory):
            self.dirLineEdit.setText(directory)

    def run_batch_check(self):
        """ run the batch checker in the appropriate mode """
        directory = self.dirLineEdit.text().strip()
        regex = self.regexLineEdit.text().strip()

        if not regex:
            regex = '.*'
        self.logger.info('Directory: %s' % directory)
        self.logger.info('Regex: %s' % regex)

        if not os.path.isdir(directory):
            self.logger.error('Please make sure the directory is valid.')
            return

        if self.recurse_checkbox.isChecked():
            recurse = True
        else:
            recurse = False

        if self.warning_checkbox.isChecked():
            warnings = True
        else:
            warnings = False

        if self.verboseCheckbox.isChecked():
            verbose = True
        else:
            verbose = False

        if self.batchCheckbox.isChecked():
            launch_batch_check(directory, file_type='.mb', warnings=warnings, verbose=verbose, recurse=recurse,
                               regex=regex)
        else:
            batch_check(directory, file_type='.mb', warnings=warnings, verbose=verbose, recurse=recurse, regex=regex)
        self.close()


def batch_check(directory, file_type='.mb', warnings=False, verbose=False, recurse=True, regex=None, open_log=True):
    """ function to check all maya scene files in a directory """
    maya_files = []
    # build list of all maya files to check
    if recurse:
        for root, dirs, files in os.walk(directory):
            for f in files:
                # ignore reference files
                if 'Reference' in root:
                    continue
                if f.endswith(file_type):
                    if regex:
                        if re.search(regex, f):
                            maya_files.append(os.path.join(root, f))
                    else:
                        maya_files.append(os.path.join(root, f))
    else:
        # just list the directory if we're not recursing the tree
        for f in os.listdir(directory):
            if f.endswith(file_type):
                if regex:
                    if re.search(regex, f):
                        maya_files.append(os.path.join(directory, f))
                else:
                    maya_files.append(os.path.join(directory, f))

    # set up output log
    logger = logging.getLogger(__name__).getChild('batchCheck')
    logger.setLevel(logging.INFO)
    log_path = os.path.join(directory, os.path.basename(directory) + '_checkerLog.txt')
    if os.path.exists(log_path):
        os.remove(log_path)
    file_handler = logging.FileHandler(log_path)
    log_formatter = logging.Formatter('[%(levelname)s]   %(message)s\r\n')
    file_handler.setFormatter(log_formatter)

    # add log from parent level checkers if verbose mode is on
    if verbose:
        checker_logger = logging.getLogger(__name__)
        checker_logger.addHandler(file_handler)
    else:
        # otherwise just log from this function
        logger.addHandler(file_handler)

    errors_found = False
    # run scan on each file
    for maya_file in maya_files:
        if verbose:
            logger.info('File: %s' % maya_file)
        else:
            print('File: %s' % maya_file)

        pmc.file(maya_file, open=True, force=True)
        checker_inst = Checker()
        checker_inst.scan()
        # get errors
        if checker_inst.has_errors():
            errors_found = True
            logger.info('Errors found in %s' % maya_file)
            errors = checker_inst.get_errors()
            for module in errors:
                logger.error(module.__name__)
                logger.error('\t' + errors[module].msg)
        # get warnings
        if checker_inst.has_warnings() and warnings:
            warnings = checker_inst.get_warnings()
            logger.info('Warnings found in %s' % maya_file)
            for module in warnings:
                logger.warning(module.__name__)

                logger.warning(warnings[module].msg)
        # add line break between file entries
        if checker_inst.has_errors() or (checker_inst.has_warnings() and warnings):
            logger.info('')
    if not errors_found:
        logger.info('No errors found')

    # clean up file handlers
    file_handler.close()
    if verbose:
        checker_logger.removeHandler(file_handler)
    else:
        logger.removeHandler(file_handler)
    if open_log:
        subprocess.Popen('notepad.exe ' + log_path)


def launch_batch_check(directory, file_type='.mb', warnings=False, verbose=False, recurse=True, regex=None):
    """ launch a local batch process to scan all files in a directory """
    # make sure directory is valid before continuing
    if not os.path.exists(directory) or not os.path.isdir(directory):
        raise Exception('Please provide a valid directory')
    cmd_string = (
                  'mayapy.exe -c "import dcc.maya.validation.checker; dcc.maya.validation.checker.batchCheck(\'' +
                  directory.replace('\\', '\\\\') +
                  '\', file_type = \'' + file_type + '\', warnings = ' + str(warnings) + ', verbose = ' + str(
                   verbose) + ', regex = \'' + str(regex) +
                  '\', recurse = ' + str(recurse) + ');"'
                  )
    subprocess.Popen(cmd_string)