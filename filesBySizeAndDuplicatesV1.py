# Find files By Size
# Duplicates

import hashlib
import traceback
from collections import defaultdict
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QFileDialog, QMessageBox, QProgressBar,
    QTabWidget, QCheckBox, QMenu
)
from PySide6.QtCore import Qt, QThread, Signal
import sys
import os

class FileSearchWorker(QThread):
    progressUpdate = Signal(int, int)
    resultsReady = Signal(list)
    errorOccured = Signal(str)

    def __init__(self, folder_path: str):
        super().__init__()
        self.folder_path = folder_path

    def run(self):
        try:
            filepaths = []
            for root, dirs, files in os.walk(self.folder_path):
                for filename in files:
                    filepaths.append(os.path.join(root, filename))

            total_files = len(filepaths)
            file_info_list = []

            for indexCount, filepath in enumerate(filepaths):
                if os.path.isfile(filepath):
                    try:
                        size = os.path.getsize(filepath)
                        filename = os.path.basename(filepath)
                        file_info_list.append((filename, filepath, size))
                    except Exception:
                        pass

                self.progressUpdate.emit(indexCount + 1, total_files)

            file_info_list.sort(key=lambda x: x[2], reverse=True)
            self.resultsReady.emit(file_info_list)

        except Exception as e:
            self.errorOccured.emit(str(e))

class FileLister(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        input_layout = QHBoxLayout()

        self.folder_input = QLineEdit()
        self.folder_input.setPlaceholderText("Enter folder path here...")

        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_folder)

        search_button = QPushButton("Search")
        search_button.clicked.connect(self.search_files)

        input_layout.addWidget(self.folder_input)
        input_layout.addWidget(browse_button)
        input_layout.addWidget(search_button)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)

        self.table_widget = QTableWidget()
        self.table_widget.setColumnCount(3)
        self.table_widget.setHorizontalHeaderLabels(["File Name", "Path", "Size (Bytes)"])
        self.table_widget.horizontalHeader().setStretchLastSection(True)

        layout.addLayout(input_layout)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.table_widget)

        self.setLayout(layout)

    def browse_folder(self):
        chosen_dir = QFileDialog.getExistingDirectory(self, "Select Directory")
        if chosen_dir:
            self.folder_input.setText(chosen_dir)

    def search_files(self):
        folder_path = self.folder_input.text().strip()
        if not folder_path or not os.path.isdir(folder_path):
            QMessageBox.warning(self, "Invalid Directory", "Please enter or select a valid folder path.")
            return

        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.table_widget.setRowCount(0)

        self.worker_thread = FileSearchWorker(folder_path)
        self.worker_thread.progressUpdate.connect(self.update_progress)
        self.worker_thread.resultsReady.connect(self.display_results)
        self.worker_thread.errorOccured.connect(self.show_error)

        self.worker_thread.start()

    def update_progress(self, current, total):
        self.progress_bar.setRange(0, total)
        self.progress_bar.setValue(current)

    def display_results(self, file_info_list):
        self.progress_bar.setVisible(False)
        self.table_widget.setRowCount(len(file_info_list))
        for row, (fname, fpath, fsize) in enumerate(file_info_list):
            self.table_widget.setItem(row, 0, QTableWidgetItem(fname))
            self.table_widget.setItem(row, 1, QTableWidgetItem(fpath))
            self.table_widget.setItem(row, 2, QTableWidgetItem(str(fsize)))

    def show_error(self, error):
        QMessageBox.critical(self, "Error", error)
        self.progress_bar.setVisible(False)

# [The DuplicateSearchWorker and DuplicateFinderTab remain unchanged]
# (Insert the DuplicateSearchWorker and DuplicateFinderTab class definitions here exactly as previously defined)
class DuplicateSearchWorker(QThread):
    progressUpdate = Signal(int, int)
    resultsReady = Signal(list)
    errorOccured = Signal(str)

    def __init__(self, folder_path: str, criteria: dict):
        super().__init__()
        self.folder_path = folder_path
        self.criteria = criteria

    def run(self):
        try:
            file_info = defaultdict(list)
            filepaths = []
            for root, _, files in os.walk(self.folder_path):
                for filename in files:
                    filepaths.append(os.path.join(root, filename))

            total_files = len(filepaths)

            for index, filepath in enumerate(filepaths):
                if os.path.isfile(filepath):
                    try:
                        criteria_list = []
                        if self.criteria['name']:
                            criteria_list.append(os.path.basename(filepath))
                        if self.criteria['size']:
                            criteria_list.append(str(os.path.getsize(filepath)))
                        if self.criteria['date']:
                            criteria_list.append(str(os.path.getmtime(filepath)))
                        if self.criteria['content']:
                            hasher = hashlib.md5()
                            with open(filepath, 'rb') as afile:
                                buf = afile.read(65536)
                                while buf:
                                    hasher.update(buf)
                                    buf = afile.read(65536)
                            criteria_list.append(hasher.hexdigest())

                        file_info[tuple(criteria_list)].append(filepath)
                    except Exception:
                        pass

                self.progressUpdate.emit(index + 1, total_files)

            duplicates = [files for files in file_info.values() if len(files) > 1]
            self.resultsReady.emit(duplicates)

        except Exception as e:
            self.errorOccured.emit(str(e))


class DuplicateFinderTab(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()
        input_layout = QHBoxLayout()

        self.folder_input = QLineEdit()
        self.folder_input.setPlaceholderText("Enter folder path here...")

        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_folder)

        search_button = QPushButton("Find Duplicates")
        search_button.clicked.connect(self.find_duplicates)

        input_layout.addWidget(self.folder_input)
        input_layout.addWidget(browse_button)
        input_layout.addWidget(search_button)

        criteria_layout = QHBoxLayout()
        self.criteria = {
            'name': QCheckBox("File Name"),
            'size': QCheckBox("File Size"),
            'date': QCheckBox("Modification Date"),
            'content': QCheckBox("File Content (Hash)")
        }
        for cb in self.criteria.values():
            cb.setChecked(True)
            criteria_layout.addWidget(cb)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)

        self.table_widget = QTableWidget()
        self.table_widget.setColumnCount(1)
        self.table_widget.setHorizontalHeaderLabels(["Duplicate File Paths"])
        self.table_widget.horizontalHeader().setStretchLastSection(True)
        self.table_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table_widget.customContextMenuRequested.connect(self.show_context_menu)

        layout.addLayout(input_layout)
        layout.addLayout(criteria_layout)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.table_widget)

        self.setLayout(layout)

    def browse_folder(self):
        chosen_dir = QFileDialog.getExistingDirectory(self, "Select Directory")
        if chosen_dir:
            self.folder_input.setText(chosen_dir)

    def find_duplicates(self):
        folder_path = self.folder_input.text().strip()
        if not folder_path or not os.path.isdir(folder_path):
            QMessageBox.warning(self, "Invalid Directory", "Please enter or select a valid folder path.")
            return

        criteria_selected = {key: cb.isChecked() for key, cb in self.criteria.items()}

        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.table_widget.setRowCount(0)

        self.worker_thread = DuplicateSearchWorker(folder_path, criteria_selected)
        self.worker_thread.progressUpdate.connect(self.update_progress)
        self.worker_thread.resultsReady.connect(self.display_results)
        self.worker_thread.errorOccured.connect(self.show_error)

        self.worker_thread.start()

    def update_progress(self, current, total):
        self.progress_bar.setRange(0, total)
        self.progress_bar.setValue(current)

    def display_results(self, duplicates):
        self.progress_bar.setVisible(False)
        for group in duplicates:
            for filepath in group:
                row = self.table_widget.rowCount()
                self.table_widget.insertRow(row)
                self.table_widget.setItem(row, 0, QTableWidgetItem(filepath))

    def show_error(self, error):
        QMessageBox.critical(self, "Error", error)
        self.progress_bar.setVisible(False)

    def show_context_menu(self, position):
        menu = QMenu()
        copy_action = menu.addAction("Copy File Path")
        action = menu.exec(self.table_widget.viewport().mapToGlobal(position))
        if action == copy_action:
            selected_items = self.table_widget.selectedItems()
            if selected_items:
                QApplication.clipboard().setText(selected_items[0].text())
                
class MainApp(QTabWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("File Utility")

        self.file_lister_tab = FileLister()
        self.addTab(self.file_lister_tab, "Files by Size")

        self.duplicate_finder_tab = DuplicateFinderTab()
        self.addTab(self.duplicate_finder_tab, "Find Duplicates")

def main():
    app = QApplication(sys.argv)
    window = MainApp()
    window.resize(900, 600)
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
