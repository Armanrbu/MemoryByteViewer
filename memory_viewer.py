import sys
import re
import pymem
import pymem.exception
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit,
    QTextEdit, QPushButton, QVBoxLayout, QGridLayout,
    QMessageBox
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import QHBoxLayout
from PyQt5.QtWidgets import QInputDialog
import psutil
import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QTextEdit, QVBoxLayout, QHBoxLayout, QGridLayout, QInputDialog, QMessageBox
)
import pymem.memory
import ctypes
from ctypes import wintypes
from ctypes import wintypes, c_size_t
from PyQt5.QtWidgets import QLabel, QSpinBox
from PyQt5.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QTextCursor
from PyQt5.QtWidgets import QDialog, QListWidget, QDialogButtonBox
import os
from PyQt5.QtWidgets import QDialog, QListWidget, QDialogButtonBox
from PyQt5.QtWidgets import QCheckBox
from PyQt5.QtGui import QIcon

# --- Windows memory protection constants ---

PAGE_READWRITE = 0x04
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000

# --- Setup WinAPI: VirtualProtectEx for temporarily changing page protection ---

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
VirtualProtectEx = kernel32.VirtualProtectEx
VirtualProtectEx.argtypes = [
    wintypes.HANDLE, 
    wintypes.LPVOID,  
    c_size_t,         
    wintypes.DWORD,   
    ctypes.POINTER(wintypes.DWORD)  
]
VirtualProtectEx.restype = wintypes.BOOL


class HexHighlighter(QSyntaxHighlighter):
    """
    Syntax highlighter for the hex editor text area.
    Responsibilities:
    - Visually marks invalid hex tokens (wrong length / non-hex chars) with a wavy underline.
    - Highlights modified bytes (indices present in self.modified_indices) in a different color.
    - Used only for display / visual feedback. It does not change underlying data.
    """

    def __init__(self, parent, modified_indices_ref):
        """
        :param parent: QTextDocument associated with QTextEdit.
        :param modified_indices_ref: A reference to a shared set of indices of modified bytes.
        """
        super().__init__(parent)
        self.modified_indices = modified_indices_ref
        
         # Regex for validating a single hex token (e.g. "0A" or "[0A]")
        self.hex_pattern = re.compile(r'^\[?[0-9A-Fa-f]{2}\]?$')  # Anchored with ^ and $
        
        # Formatting setups
        self.modified_format = QTextCharFormat()
        self.modified_format.setForeground(QColor('#FF5555'))

        # Format for invalid tokens
        self.invalid_format = QTextCharFormat()
        self.invalid_format.setUnderlineColor(QColor('#FFD700'))
        self.invalid_format.setUnderlineStyle(QTextCharFormat.WaveUnderline)

    def highlightBlock(self, text):
        """
        Called automatically by Qt for each text block.

        - Splits the line into space-separated tokens.
        - Validates each token as hex.
        - Applies formatting based on validity and modification status.
        """
        parts = text.split()
        pos = 0
        
        for idx, part in enumerate(parts):
            # Validate token against the hex pattern
            is_valid = self.hex_pattern.fullmatch(part) is not None
            
            # Find the position of this token in the block text
            start = text.find(part, pos)
            if start == -1:
                continue
            end = start + len(part)
            
            # Apply formatting based on validation and modification
            if not is_valid:
                self.setFormat(start, end - start, self.invalid_format)
            elif idx in self.modified_indices:
                self.setFormat(start, end - start, self.modified_format)
            
            pos = end + 1



class PatternSearchDialog(QDialog):
    """
    Dialog for searching a hex pattern in the target process memory.

    Features:
    - Input pattern with wildcards (e.g. "A1 ?? 00 FF ??").
    - Scans process memory (main module or fallback range).
    - Shows list of matching addresses with module names.
    - Double-click or OK to select an address.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Pattern Search")
        self.setFixedSize(600, 500)
        # Inherit dark theme / styles from parent
        self.setStyleSheet(parent.styleSheet())
        
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 15, 20, 10)  # (left, top, right, bottom)
        
        # --- Pattern input row ---
        pattern_layout = QHBoxLayout()
        pattern_layout.addWidget(QLabel("Pattern:"))
        self.pattern_input = QLineEdit()
        self.pattern_input.setPlaceholderText("Enter hex pattern (e.g., 'A1 ?? ?? 00 1B')")
        pattern_layout.addWidget(self.pattern_input)
        layout.addLayout(pattern_layout)
        
        # Search button
        self.search_button = QPushButton("Search Memory")
        self.search_button.clicked.connect(self.search)
        layout.addWidget(self.search_button)
        
        # Status label
        self.status_label = QLabel("Ready to search")
        layout.addWidget(self.status_label)
        
        # Results list
        layout.addWidget(QLabel("Search Results:"))
        self.results_list = QListWidget()
        self.results_list.itemDoubleClicked.connect(self.accept)
        layout.addWidget(self.results_list)
        
        # --- Dialog buttons (OK / Cancel) ---
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        self.setLayout(layout)
        self.results = []          # Stores found addresses in parallel with list items
    
    def search(self):
        """
        Perform pattern search in the target process memory.

        - Ensures process handle exists (tries to open if needed).
        - Parses pattern with optional wildcards (??).
        - Scans memory in chunks to avoid freezing the UI.
        - Stores up to 1000 matches to keep things responsive.
        """
        # Get the parent viewer
        viewer = self.parent()
        
        # Ensure a process is opened
        if not viewer.pm or not hasattr(viewer.pm, 'process_handle'):
            # Try to open the process if not already open
            process_name = viewer.process_input.text().strip()
            if not process_name:
                QMessageBox.warning(self, "Error", "No process specified!")
                return
                
            try:
                if viewer.pm:
                    viewer.pm.close_process()
                viewer.pm = pymem.Pymem(process_name)
                QApplication.processEvents()  # Update UI
            except pymem.exception.ProcessNotFound:
                QMessageBox.warning(self, "Error", f"Process '{process_name}' not found!")
                return
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Error opening process: {str(e)}")
                return
        
        # Now proceed with pattern search
        pattern = self.pattern_input.text().strip()
        if not pattern:
            QMessageBox.warning(self, "Error", "Please enter a pattern!")
            return
        
        # Convert pattern to bytes with wildcards
        try:
            pattern_bytes = []
            pattern_parts = pattern.split()
            for part in pattern_parts:
                if part == "??":
                    pattern_bytes.append(None)  # Wildcard
                else:
                    pattern_bytes.append(int(part, 16))
        except ValueError:
            QMessageBox.warning(self, "Error", "Invalid pattern format!")
            return
        
        self.results_list.clear()
        self.results = []
        found_count = 0
        
        # Get main module
        try:
            main_module = viewer.pm.process_handle
            module_info = pymem.process.module_from_name(viewer.pm.process_handle, viewer.process_input.text().strip())
            base_address = module_info.lpBaseOfDll
            module_size = module_info.SizeOfImage
        except:
            base_address = 0
            module_size = 0x7FFFFFFF  # Scan entire memory if module not found
        
        self.status_label.setText("Searching...")
        QApplication.processEvents()
        
        # Search in 10MB chunks to avoid freezing
        chunk_size = 10 * 1024 * 1024
        current_address = base_address
        
        while current_address < base_address + module_size:
            # Read memory chunk
            try:
                chunk_end = min(current_address + chunk_size, base_address + module_size)
                chunk_data = viewer.pm.read_bytes(current_address, chunk_end - current_address)
            except:
                current_address += chunk_size
                continue
            
            # Search in current chunk
            for i in range(len(chunk_data) - len(pattern_bytes) + 1):
                match = True
                for j, pattern_byte in enumerate(pattern_bytes):
                    if pattern_byte is not None and chunk_data[i+j] != pattern_byte:
                        match = False
                        break
                
                if match:
                    address = current_address + i
                    self.results.append(address)
                    
                    # Try to get module name
                    module_name = "Unknown"
                    try:
                        module_info = viewer.pm.process.get_module_from_address(address)
                        if module_info:
                            module_path = module_info.filename
                            module_name = os.path.basename(module_path)
                    except:
                        pass
                    
                    self.results_list.addItem(f"{hex(address)} ({module_name})")
                    found_count += 1
                    
                    # Limit results to 1000 to prevent freezing
                    if found_count >= 1000:
                        self.results_list.addItem("Stopped after 1000 matches")
                        self.status_label.setText(f"Found {found_count} matches")
                        return
            
            current_address += chunk_size
            self.status_label.setText(f"Searching... Scanned {hex(current_address)}")
            QApplication.processEvents()
        
        if found_count == 0:
            self.results_list.addItem("No matches found")
        else:
            self.results_list.addItem(f"Found {found_count} matches")
        
        self.status_label.setText(f"Search completed. Found {found_count} matches")
    
    def selected_address(self):
        """Return the currently selected address"""
        current_row = self.results_list.currentRow()
        if 0 <= current_row < len(self.results):
            return self.results[current_row]
        return None


class MemoryByteViewerDark(QWidget):
    """
    Main GUI class for Memory Byte Viewer.
    Features:
    - Attach to a target process by name.
    - Read bytes around a specific memory address.
    - Highlight center byte, allow editing in hex.
    - Track modified bytes and show them visually.
    - Commit changes to target process using safe memory protection changes.
    - Auto-refresh view and pattern search dialog.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Memory Byte Viewer")
        self.setWindowIcon(QIcon("assets/logo.png"))
        self.setFixedSize(595, 465) #530

        self.pm = None
        self.ignore_text_changes = False
        self.original_bytes = bytearray()
        self.current_start_address = 0
        self.current_bytes_before = 0
        self.modified_indices = set()
        self.timer = QTimer()
        self.timer.timeout.connect(self.read_memory)

        self.init_ui()  

        self.highlighter = HexHighlighter(self.memory_view.document(), self.modified_indices)

  


    def init_ui(self):
        self.setStyleSheet("""
    
        QPushButton#process_button {
            min-width: 30px;
            max-width: 30px;
        }
                           
    QWidget {
        background-color: #161717;
        color: #dcdcdc;
        font-family: Consolas;
        font-size: 10pt;
    }

    QLineEdit{
    
        background-color: #242626;
        color: #d9d9d9 ;
        border: none;
        padding: 4px;
        border-radius: 3px;  /* You can tweak the number */
        font-weight: bold;
                   height: 20px;
        padding: 5px;
        font-size: 13px;    

                           
                           
                           
    }
    
    QListWidget,QTextEdit {
                            min-height: 165px;
        background-color: #0C0D0D;
        color: #1fa3a3;
        border: 1px solid #555;
        padding: 4px;
        border-radius: 6px;  /* You can tweak the number */

                           
    }

    QPushButton {
        font-family: "Segoe UI";
        background-color: #242626;
        color: #c5c8c6;
        padding: 6px 12px;
        font-size: 10pt;
        border-radius: 5px;  /* You can tweak the number */
        font-weight: bold;
    }

    QPushButton:hover {
        background-color: rgba(0, 255, 153, 0.1);
        color: #1A9347;
                           
    
    }

    QLabel#patternLabel,QLabel {
        font-family: "Segoe UI";         
        color: #c4c4c4;
                           
        
                           
    }
                           
        QSpinBox {
        background-color: #242626;
        color: #d9d9d9;
        
        border-radius: 3px;
        padding: 2px;
        selection-background-color: #1A9347;
    }
    QSpinBox::up-button, QSpinBox::down-button {
        width: 20px;
        border-left: 1px solid #555;
    }
    QSpinBox::up-button:hover, QSpinBox::down-button:hover {
        background-color: rgba(0, 255, 153, 0.1);
    }
    QSpinBox::up-arrow, QSpinBox::down-arrow {
        image: none;
        width: 0;
        height: 0;
    }
                           
          QSpinBox {
        height: 20px;
        padding: 5px;
        font-size: 14px;
    }                 
                               QListWidget {
        background-color: #121212;
        color: #E0E0E0;
        font-size: 12px;
        font-family: 'Segoe UI', 'Consolas', 'Courier New', monospace;
        border-radius: 4px;
    }

    QScrollBar:vertical {
        background: transparent;
        width: 8px;
        margin: 0px;
    }

    QScrollBar::handle:vertical {
        background: #5a5a5a;
        border-radius: 4px;
        min-height: 25px;
    }

    QScrollBar::handle:vertical:hover {
        background: #7a7a7a;
    }

    QScrollBar::add-line:vertical,
    QScrollBar::sub-line:vertical {
        background: none;
        height: 0px;
    }

    QScrollBar::add-page:vertical,
    QScrollBar::sub-page:vertical {
        background: none;
    }

    QScrollBar:horizontal {
        background: transparent;
        height: 8px;
        margin: 0px;
    }

    QScrollBar::handle:horizontal {
        background: #5a5a5a;
        border-radius: 4px;
        min-width: 25px;
    }

    QScrollBar::handle:horizontal:hover {
        background: #7a7a7a;
    }

    QScrollBar::add-line:horizontal,
    QScrollBar::sub-line:horizontal {
        background: none;
        width: 0px;
    }

""")
        font = QFont("Consolas", 12)

     
        grid = QGridLayout()

        process_layout = QHBoxLayout()
        self.process_input = QLineEdit("HD-Player.exe")
        self.process_button = QPushButton("...")
        self.process_button.clicked.connect(self.show_process_list) 
        
        process_layout.addWidget(self.process_input)
        process_layout.addWidget(self.process_button)
        
        grid.addWidget(QLabel("Process Name:"), 0, 0)
        grid.addLayout(process_layout, 0, 1)
        

        grid.addWidget(QLabel("Memory Address:"), 1, 0)
        self.address_input = QLineEdit("")
        grid.addWidget(self.address_input, 1, 1)

     
        grid.addWidget(QLabel("Bytes Before:"), 2, 0)
        self.before_input = QSpinBox()
        self.before_input.setRange(0, 1024)
        self.before_input.setValue(0)
        self.before_input.setButtonSymbols(QSpinBox.NoButtons)  
        grid.addWidget(self.before_input, 2, 1)

        grid.addWidget(QLabel("Bytes After:"), 3, 0)
        self.after_input = QSpinBox()
        self.after_input.setRange(0, 1024)
        self.after_input.setValue(0)
        self.after_input.setButtonSymbols(QSpinBox.NoButtons)  
        grid.addWidget(self.after_input, 3, 1)

        # Add this after the existing buttons in your grid layout
        grid.addWidget(QLabel("Pattern Search:"), 4, 0)
        self.find_button = QPushButton("Find Pattern")
        self.find_button.clicked.connect(self.find_pattern)
        grid.addWidget(self.find_button, 4, 1)

        # Memory bytes section
        label = QLabel("Surrounding Bytes (Hex - Center Byte Marked with [] ,Editable):")
        self.memory_view = QTextEdit()
        self.memory_view.setFont(font)

        # Buttons at the bottom
        button_layout = QHBoxLayout()
        self.read_button = QPushButton("Read Memory")
        self.auto_button = QPushButton("Start Auto-Refresh")
        self.commit_button = QPushButton("Commit Changes")

        

        for btn in [self.read_button, self.auto_button, self.commit_button]:
            btn.setFixedHeight(35)
            button_layout.addWidget(btn)

        # Status label
        self.status_label = QLabel()
        self.status_label.setAlignment(Qt.AlignCenter)

        # Combine everything
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(25, 10, 25, 6)  # (left, top, right, bottom)

        main_layout.addLayout(grid)
        main_layout.addWidget(label)
        main_layout.addWidget(self.memory_view)
        main_layout.addSpacing(1)
        main_layout.addLayout(button_layout)
        main_layout.addWidget(self.status_label)

        self.setLayout(main_layout)

        # Connect buttons
        self.read_button.clicked.connect(self.read_memory)
        self.auto_button.clicked.connect(self.toggle_auto_refresh)
        self.commit_button.clicked.connect(self.commit_changes)

        self.before_input.valueChanged.connect(self.handle_spin_changes)
        self.after_input.valueChanged.connect(self.handle_spin_changes)
        self.memory_view.textChanged.connect(self.handle_text_edit)


    def memory_regions(self):
        """Get all memory regions in the process"""
        if not self.pm:
            return []
        
        regions = []
        address = 0
        while address < 0x7FFFFFFF:  # Max 32-bit address space
            try:
                mbi = pymem.memory.virtual_query(self.pm.process_handle, address)
                regions.append(mbi)
                address = mbi.BaseAddress + mbi.RegionSize
            except pymem.exception.WinAPIError:
                break
            except Exception as e:
                print(f"Error querying memory: {e}")
                break
        
        return regions
        
        
    def find_pattern(self):
        try:
            dialog = PatternSearchDialog(self)
            if dialog.exec_() == QDialog.Accepted:
                address = dialog.selected_address()
                if address:
                    self.address_input.setText(hex(address))
                    self.read_memory()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Pattern search failed: {str(e)}")   

    def list_modules(self):
        if not self.pm:
            return []
        return list(self.pm.list_modules())

    def handle_spin_changes(self):
        """Handle changes in spin box values"""
        if self.timer.isActive():  # Auto-refresh if enabled
            self.read_memory()

    def show_process_list(self):
            """Display running processes in a dialog"""
            try:
                processes = []
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        processes.append(f"{proc.info['name']} (PID: {proc.info['pid']})")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                if not processes:
                    QMessageBox.warning(self, "Warning", "No processes found!")
                    return

                process, ok = QInputDialog.getItem(
                    self,
                    "Select Process",
                    "Running Processes:",
                    sorted(processes),
                    0,
                    False
                )

                if ok and process:
                    selected_name = process.split(' (PID')[0].strip()
                    self.process_input.setText(selected_name)

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to get processes: {str(e)}")


    def commit_changes(self):
        if not self.pm or not self.original_bytes:
            self.show_error("No memory read to commit.")
            return

        text = self.memory_view.toPlainText()
        hex_values = re.findall(r'\[?([0-9A-Fa-f]{2})\]?', text)

        try:
            new_bytes = [int(hv, 16) for hv in hex_values]
        except ValueError:
            self.show_error("Invalid hex values detected.")
            return

        if len(new_bytes) != len(self.original_bytes):
            self.show_error("Byte count mismatch.")
            return

        try:
            # Find modified bytes
            modified = []
            for i in range(len(new_bytes)):
                if new_bytes[i] != self.original_bytes[i]:
                    modified.append((i, new_bytes[i]))

            if not modified:
                self.show_error("No changes detected.")
                return

            # Get memory range to modify
            start_offset = modified[0][0]
            end_offset = modified[-1][0]
            data_to_write = bytes(new_bytes[start_offset:end_offset+1])
            write_address = self.current_start_address + start_offset
            write_size = len(data_to_write)

            # Get process handle
            process_handle = self.pm.process_handle

            # Change memory protection
            old_protect = wintypes.DWORD()
            success = VirtualProtectEx(
                process_handle,
                write_address,
                write_size,
                PAGE_READWRITE,
                ctypes.byref(old_protect)
            )

            if not success:
                error = ctypes.get_last_error()
                self.show_error(f"Failed to change protection: Windows error {error}")
                return

            # Write memory
            self.pm.write_bytes(write_address, data_to_write, write_size)

            # Restore original protection
            VirtualProtectEx(
                process_handle,
                write_address,
                write_size,
                old_protect,
                ctypes.byref(wintypes.DWORD()))

            # Update original bytes
            self.original_bytes = bytearray(new_bytes)
            self.status_label.setText("Changes committed successfully.")
            self.status_label.setStyleSheet("color: #1A9347;")
            self.modified_indices.clear()
            self.highlighter.rehighlight()

        except pymem.exception.MemoryWriteError as e:
            self.show_error(f"Failed to write memory: {str(e)}")
        except Exception as e:
            self.show_error(f"Error writing memory: {str(e)}")


    def read_memory(self):
        self.status_label.clear()
        process_name = self.process_input.text().strip()
        address_str = self.address_input.text().strip()
        bytes_before = self.before_input.value()
        bytes_after = self.after_input.value()

        try:
            address = int(address_str, 16)
            if bytes_before < 0 or bytes_after < 0:
                raise ValueError
        except ValueError:
            self.show_error("Invalid input values.")
            return

        try:
            if self.pm:
                self.pm.close_process()
            self.pm = pymem.Pymem(process_name)
        except pymem.exception.ProcessNotFound:
            self.show_error(f"Process '{process_name}' not found.")
            return
        except Exception as e:
            self.show_error(f"Error accessing process: {str(e)}")
            return

        start_address = address - bytes_before
        length = bytes_before + 1 + bytes_after

        if start_address < 0:
            self.show_error("Invalid address after adjusting bytes before.")
            return

        try:
            bytes_read = self.pm.read_bytes(start_address, length)
        except pymem.exception.MemoryReadError as e:
            error_msg = f"Failed to read memory: {e}"
            if "299" in str(e):
                error_msg += "\nTip: The memory might be inaccessible. Try reducing 'Bytes Before/After'."
            self.show_error(error_msg)
            return
        except Exception as e:
            self.show_error(f"Error reading memory: {str(e)}")
            return

        self.original_bytes = bytearray(bytes_read)
        self.current_start_address = start_address
        self.current_bytes_before = bytes_before

        hex_bytes = []
        for i, b in enumerate(bytes_read):
            hex_str = f"[{b:02X}]" if i == bytes_before else f"{b:02X}"
            hex_bytes.append(hex_str)

        # Update text with flag protection
        self.ignore_text_changes = True
        self.memory_view.setPlainText(' '.join(hex_bytes))
        self.ignore_text_changes = False

        self.status_label.setText("Memory read successfully.")
        self.status_label.setStyleSheet("color: #1A9347;")
        self.modified_indices.clear()
        self.highlighter.rehighlight()

    def handle_text_edit(self):
        if getattr(self, "ignore_text_changes", False) or not hasattr(self, 'original_bytes') or not self.original_bytes:
            return

        self.ignore_text_changes = True  # 👈 Start guarding

        try:
            cursor = self.memory_view.textCursor()
            scroll_pos = self.memory_view.verticalScrollBar().value()

            parts = self.memory_view.toPlainText().split()
            self.modified_indices.clear()

            max_index = min(len(parts), len(self.original_bytes)) - 1
            for idx in range(max_index + 1):
                part = parts[idx]
                try:
                    clean_part = part.strip('[]')
                    if len(clean_part) != 2:
                        continue
                    current_byte = int(clean_part, 16)
                    if current_byte != self.original_bytes[idx]:
                        self.modified_indices.add(idx)
                except ValueError:
                    pass

            self.highlighter.rehighlight()  # 👈 This can trigger textChanged in some setups
            self.memory_view.setTextCursor(cursor)
            self.memory_view.verticalScrollBar().setValue(scroll_pos)

        finally:
            self.ignore_text_changes = False  # 👈 Always reset even if something goes wrong


    def select_process(self):
        processes = []
        for proc in psutil.process_iter(['pid', 'name']):
            processes.append(f"{proc.info['name']} (PID: {proc.info['pid']})")
        
        process, ok = QInputDialog.getItem(
            self, "Select Process", "Running Processes:", processes, 0, False
        )
        if ok:
            self.process_input.setText(process.split(' (PID')[0])

    

    def toggle_auto_refresh(self):
        if self.timer.isActive():
            self.timer.stop()
            self.auto_button.setText("Start Auto-Refresh")
            self.status_label.setText("Auto-refresh stopped.")
            self.status_label.setStyleSheet("color: #dcdcdc;")
        else:
            self.timer.start(1000)
            self.auto_button.setText("Stop Auto-Refresh")
            self.status_label.setText("Auto-refresh started...")
            self.status_label.setStyleSheet("color: #1A9347;")

    def show_error(self, message):
        self.status_label.setText(message)
        self.status_label.setStyleSheet("color: red;")
        if self.timer.isActive():
            self.timer.stop()
            self.auto_button.setText("Start Auto-Refresh")

    def closeEvent(self, event):
        if self.pm:
            self.pm.close_process()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    viewer = MemoryByteViewerDark()
    viewer.show()
    sys.exit(app.exec_())
