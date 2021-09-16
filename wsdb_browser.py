#
# wsdb_browser.py
# GUI tool for browsing wsdb files
#
# Developer Alexander <dev@alex-mails.de>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

import sys
import time
import datetime
from sqlite3 import connect, Connection, Cursor
from typing import List, Dict, Tuple, Optional, Union

from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *


class TreeItem:
    def __init__(self):
        self.id: int = 0
        self.parent: Optional["TreeItem"] = None
        self.children: Dict[int, "TreeItem"] = {}
        self.field_type: Optional[str] = None
        self.field_name: Optional[str] = None
        self.field_display_name: Optional[str] = None
        self.packet: Optional["Packet"] = None
        self.buffer: Optional[bytes] = None
        self.position: int = 0
        self.length: int = 0
        self.integer_value: int = 0
        self.double_value: float = 0.0
        self.string_value: Optional[str] = None
        self.representation: Optional[str] = None

    def __str__(self):
        return self.field_name if self.field_name is not None else str(id)

    def get_gui_representation(self) -> str:
        # if there is a representation string it has priority
        if self.representation is not None:
            return self.representation

        if self.field_type is None:
            return self.field_name

        if self.field_type == "FT_PROTOCOL":
            return f"{self.field_display_name}: {self.string_value}"
        elif self.field_type == "FT_INT8" or self.field_type == "FT_UINT8":
            return f"{self.field_display_name}: {self.integer_value} (0x{self.integer_value:02X})"
        elif self.field_type == "FT_INT16" or self.field_type == "FT_UINT16":
            return f"{self.field_display_name}: {self.integer_value} (0x{self.integer_value:04X})"
        elif self.field_type == "FT_INT24" or self.field_type == "FT_UINT24":
            return f"{self.field_display_name}: {self.integer_value} (0x{self.integer_value:06X})"
        elif self.field_type == "FT_INT32" or self.field_type == "FT_UINT32":
            return f"{self.field_display_name}: {self.integer_value} (0x{self.integer_value:08X})"
        elif self.field_type == "FT_INT40" or self.field_type == "FT_UINT40":
            return f"{self.field_display_name}: {self.integer_value} (0x{self.integer_value:10X})"
        elif self.field_type == "FT_INT48" or self.field_type == "FT_UINT48":
            return f"{self.field_display_name}: {self.integer_value} (0x{self.integer_value:12X})"
        elif self.field_type == "FT_INT56" or self.field_type == "FT_UINT56":
            return f"{self.field_display_name}: {self.integer_value} (0x{self.integer_value:14X})"
        elif self.field_type == "FT_INT64":
            return f"{self.field_display_name}: {self.integer_value} (0x{self.integer_value:16X})"
        elif self.field_type == "FT_UINT64" or self.field_type == "FT_EUI64":
            uint64_value: int = self.integer_value + 0x8000000000000000 if self.double_value > 0.0 else self.integer_value
            return f"{self.field_display_name}: {uint64_value} (0x{self.integer_value:16X})"
        elif self.field_type == "FT_FLOAT" or self.field_type == "FT_DOUBLE":
            return f"{self.field_display_name}: {self.double_value}"
        elif self.field_type == "FT_ABSOLUTE_TIME":
            absolute_timestamp = datetime.datetime(year=1970, month=1, day=1, hour=0, minute=0, second=0) + datetime.timedelta(seconds=self.double_value)
            time_value: str = absolute_timestamp.isoformat()
            return f"{self.field_display_name}: {time_value} ({self.double_value} s)"
        elif self.field_type == "FT_RELATIVE_TIME":
            return f"{self.field_display_name}: {self.double_value:.9f} s"
        elif self.field_type == "FT_BOOLEAN":
            boolean_value: bool = False if self.integer_value == 0 else True
            return f"{self.field_display_name}: {boolean_value} ({self.integer_value})"
        elif self.field_type == "FT_FRAMENUM":
            return f"{self.field_display_name}: {self.integer_value}"
        elif self.field_type == "FT_FRAMENUM" or self.field_type == "FT_IPv4":
            return f"{self.field_display_name}: {self.integer_value} (0x{self.integer_value:08X})"
        elif self.field_type == "FT_CHAR":
            return f"{self.field_display_name}: '{chr(self.integer_value)}'"
        elif self.field_type == "FT_PROTOCOL" or self.field_type == "FT_STRING" or self.field_type == "FT_STRINGZ" or self.field_type == "FT_STRINGZPAD" or self.field_type == "FT_STRINGZTRUNC":
            return f"{self.field_display_name}: {self.string_value}"
        elif self.field_type == "FT_GUID" or self.field_type == "FT_ETHER" or self.field_type == "FT_BYTES" or self.field_type == "FT_IPv6":
            return f"{self.field_display_name}: {self.string_value}"

        return self.field_name


class Packet:
    def __init__(self):
        self.id: int = 0
        self.timestamp: float = 0.0
        self.length: int = 0
        self.interface_id: int = 0
        self.source: Optional[str] = None
        self.destination: Optional[str] = None
        self.info: Optional[str] = None
        self.protocol: Optional[str] = None
        self.buffers: Dict[int, bytes] = {}
        self.tree: TreeItem = TreeItem()

    def __str__(self):
        return f"{self.id}: {self.info}" if self.info is not None else str(id)


def show_message_box(text: str):
    message_box = QMessageBox()
    message_box.setIcon(QMessageBox.Critical)
    message_box.setText(text)
    message_box.show()


class MyTableWidget(QTableWidget):
    def __init__(self, main_window: "MainWindow"):
        super().__init__()
        self.main_window = main_window

    def verticalScrollbarValueChanged(self, value: int) -> None:
        super().verticalScrollbarValueChanged(value)
        self.main_window.set_visible_packets_in_packet_list()

    def resizeEvent(self, e: QResizeEvent) -> None:
        super().resizeEvent(e)
        self.main_window.set_visible_packets_in_packet_list()


class MainWindow(QMainWindow):
    def cleanup(self):
        for database in self.databases:
            try:
                database.close()
            except Exception as ex:
                show_message_box(str(ex))

        self.file_paths = []
        self.databases = []
        self.packet_ids = []

        self.clear()

    def clear(self):
        self.packet_list.clear()
        self.protocol_tree.clear()
        self.buffer_view_container.clear()

    def get_packet(self, packet_id: int) -> Optional[Packet]:
        packet: Optional[Packet] = None

        cursors: List[Cursor] = [database.cursor() for database in self.databases]
        for cursor in cursors:

            command: str = \
                """
                SELECT packet.timestamp, packet.length, packet.interface_id, source_string.string AS source, destination_string.string AS destination, info_string.string AS info, protocol_string.string AS protocol, buffer.id, buffer.buffer
                FROM packet
                LEFT JOIN string AS source_string ON packet.source_string_id = source_string.id
                LEFT JOIN string AS destination_string ON packet.destination_string_id = destination_string.id
                LEFT JOIN string AS info_string ON packet.info_string_id = info_string.id
                LEFT JOIN string AS protocol_string ON packet.protocol_string_id = protocol_string.id
                LEFT JOIN buffer ON packet.id = buffer.packet_id
                WHERE packet.id = ?;
                """
            cursor.execute(command, (packet_id,))

            rows = cursor.fetchall()

            if len(rows) == 0:
                continue

            packet = Packet()
            packet.id = packet_id
            for row in rows:
                packet.timestamp = row[0]
                packet.length = row[1]
                packet.interface_id = row[2]
                packet.source = row[3]
                packet.destination = row[4]
                packet.info = row[5]
                packet.protocol = row[6]
                packet.buffers[row[7]] = row[8]

            command = \
                """
                SELECT tree.id, tree.parent_id, field_type.type, field.name, field.display_name, tree.buffer_id, tree.position, tree.length, tree.double_value, tree.integer_value, string_value_string.string, representation_string.string
                FROM tree
                LEFT JOIN field ON tree.field_id = field.id
                LEFT JOIN field_type ON field.field_type_id = field_type.id
                LEFT JOIN string AS string_value_string ON tree.string_value_string_id = string_value_string.id
                LEFT JOIN string AS representation_string ON tree.representation_string_id = representation_string.id
                WHERE tree.packet_id = ?
                ORDER BY tree.id;
                """
            cursor.execute(command, (packet_id,))

            rows = cursor.fetchall()

            if len(rows) == 0:
                break

            tree_items: Dict[int, TreeItem] = {0: packet.tree}
            for row in rows:
                tree_item: TreeItem = TreeItem()
                tree_item.id = row[0]
                parent_id: int = row[1]
                if parent_id in tree_items:
                    parent: TreeItem = tree_items[parent_id]
                    tree_item.parent = parent
                    parent.children[tree_item.id] = tree_item

                tree_item.field_type = row[2]
                tree_item.field_name = row[3]
                tree_item.field_display_name = row[4]

                buffer_id: int = row[5]
                if buffer_id in packet.buffers:
                    tree_item.buffer = packet.buffers[buffer_id]

                tree_item.position = row[6]
                tree_item.length = row[7]

                tree_item.double_value = row[8]
                tree_item.integer_value = row[9]

                tree_item.string_value = row[10]
                tree_item.representation = row[11]

                tree_items[tree_item.id] = tree_item

            break

        for cursor in cursors:
            cursor.close()

        return packet

    def build_packet_ids(self, command: str):
        self.packet_ids = []
        cursors: List[Cursor] = [database.cursor() for database in self.databases]

        for cursor in cursors:
            cursor.execute(command)

        # loop until no more rows can be fetched
        while True:
            packet_id: Optional[int] = None
            for cursor in cursors:
                row = cursor.fetchone()
                if row is None:
                    continue

                packet_id: int = row[0]
                self.packet_ids.append(packet_id)

            if packet_id is None:
                break

        for cursor in cursors:
            cursor.close()

        if len(self.packet_ids) > 1:
            self.packet_ids.sort()

    def get_packet_all_ids(self):
        command: str = \
            """
            SELECT packet.id
            FROM packet;
            """
        self.build_packet_ids(command)

    def prepare_packet_list(self):
        self.packet_list_label.setText(f"Packet List: {len(self.packet_ids)} Packets")
        self.packet_list.clear()
        self.packet_list.setHorizontalHeaderLabels(["Id", "Timestamp", "Length", "Protocol", "Info"])
        self.packet_list.setRowCount(len(self.packet_ids))

    def set_packet_in_packet_list(self, row_index, packet: Packet):
        packet_id_table_widget_item: QTableWidgetItem = QTableWidgetItem(str(packet.id))
        packet_id_table_widget_item.setFont(self.monospace_font)
        self.packet_list.setItem(row_index, 0, packet_id_table_widget_item)

        absolute_timestamp = datetime.datetime(year=1970, month=1, day=1, hour=0, minute=0, second=0) + datetime.timedelta(seconds=packet.timestamp)
        time_value: str = absolute_timestamp.isoformat()
        packet_timestamp_table_widget_item: QTableWidgetItem = QTableWidgetItem(time_value)
        packet_timestamp_table_widget_item.setFont(self.monospace_font)
        self.packet_list.setItem(row_index, 1, packet_timestamp_table_widget_item)

        packet_length_table_widget_item: QTableWidgetItem = QTableWidgetItem(str(packet.length))
        packet_length_table_widget_item.setFont(self.monospace_font)
        self.packet_list.setItem(row_index, 2, packet_length_table_widget_item)

        packet_protocol_table_widget_item: QTableWidgetItem = QTableWidgetItem(packet.protocol)
        packet_protocol_table_widget_item.setFont(self.monospace_font)
        self.packet_list.setItem(row_index, 3, packet_protocol_table_widget_item)

        packet_info_table_widget_item: QTableWidgetItem = QTableWidgetItem(packet.info)
        packet_info_table_widget_item.setFont(self.monospace_font)
        self.packet_list.setItem(row_index, 4, packet_info_table_widget_item)

    def set_visible_packets_in_packet_list(self):
        if len(self.packet_ids) == 0:
            return

        row_height: int = self.packet_list.rowHeight(0)
        visible_rectangle = self.packet_list.viewport().rect()
        visible_rectangle_top: int = visible_rectangle.top()
        visible_rectangle_bottom: int = visible_rectangle.bottom()
        top_index: int = 0
        bottom_index: int = len(self.packet_ids)
        mid_index: int = (top_index + bottom_index) // 2
        found: bool = False

        while top_index <= bottom_index:
            mid_index = (top_index + bottom_index) // 2
            row_position: int = self.packet_list.rowViewportPosition(mid_index)
            if row_position + row_height >= visible_rectangle_top and row_position <= visible_rectangle_bottom:
                found = True
                break
            else:
                if row_position > visible_rectangle_top:
                    bottom_index = mid_index - 1
                else:
                    top_index = mid_index + 1

        if not found:
            return

        top_index = mid_index
        bottom_index = mid_index

        while top_index > 0:
            row_position: int = self.packet_list.rowViewportPosition(top_index - 1)
            if row_position + row_height >= visible_rectangle_top and row_position <= visible_rectangle_bottom:
                top_index -= 1
            else:
                break

        while bottom_index < len(self.packet_ids) - 1:
            row_position: int = self.packet_list.rowViewportPosition(bottom_index + 1)
            if row_position + row_height >= visible_rectangle_top and row_position <= visible_rectangle_bottom:
                bottom_index += 1
            else:
                break

        for i in range(top_index, bottom_index + 1):
            packet: Packet = self.get_packet(self.packet_ids[i])
            self.set_packet_in_packet_list(i, packet)

    def add_children_to_protocol_tree(self, parent: Union[QTreeWidget, QTreeWidgetItem],
                                      children: Dict[int, "TreeItem"]):
        for child_id, child in children.items():
            tree_widget_item: QTreeWidgetItem = QTreeWidgetItem(parent, [child.get_gui_representation()])
            self.add_children_to_protocol_tree(tree_widget_item, child.children)

    def set_protocol_tree(self, packet: Packet):
        self.protocol_tree.clear()
        self.protocol_tree.setHeaderLabel(f"Packet {packet.id}: {packet.info}")
        self.add_children_to_protocol_tree(self.protocol_tree, packet.tree.children)

    def set_buffer_view(self, packet: Packet):
        self.buffer_view_container.clear()
        for buffer_id, buffer in packet.buffers.items():
            buffer_panel: QWidget = QWidget()
            buffer_panel_layout: QHBoxLayout = QHBoxLayout()
            buffer_hex_view: QTableWidget = QTableWidget()
            buffer_ascii_view: QTableWidget = QTableWidget()

            buffer_hex_view.setColumnCount(self.buffer_view_width + 1)
            buffer_hex_view.setFont(self.monospace_font)
            buffer_hex_view.setHorizontalHeaderLabels([" "] + [f"{i:1X}" for i in range(self.buffer_view_width)])
            buffer_hex_view.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)

            buffer_ascii_view.setColumnCount(self.buffer_view_width + 1)
            buffer_ascii_view.setFont(self.monospace_font)
            buffer_ascii_view.setHorizontalHeaderLabels([" "] + [f"{i:1X}" for i in range(self.buffer_view_width)])
            buffer_ascii_view.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)

            buffer_panel_layout.addWidget(buffer_hex_view)
            buffer_panel_layout.addWidget(buffer_ascii_view)

            buffer_panel.setLayout(buffer_panel_layout)
            self.buffer_view_container.addTab(buffer_panel, f"Buffer {buffer_id}")

            row_count = (len(buffer) // self.buffer_view_width) + 1
            buffer_hex_view.setRowCount(row_count)
            buffer_ascii_view.setRowCount(row_count)

            for i in range(len(buffer)):
                current_byte = buffer[i]
                hex_string: str = f"{current_byte:02X}"
                ascii_string: str = f"{chr(current_byte)}"
                if not ascii_string.isprintable():
                    ascii_string = "�"
                row: int = i // self.buffer_view_width
                column: int = (i % self.buffer_view_width) + 1
                hex_table_widget_item: QTableWidgetItem = QTableWidgetItem(hex_string)
                hex_table_widget_item.setFont(self.monospace_font)
                buffer_hex_view.setItem(row, column, hex_table_widget_item)

                ascii_table_widget_item: QTableWidgetItem = QTableWidgetItem(ascii_string)
                ascii_table_widget_item.setFont(self.monospace_font)
                buffer_ascii_view.setItem(row, column, ascii_table_widget_item)

            for i in range(row_count):
                row: int = i
                column: int = 0
                address_string: str = f"{self.buffer_view_width * i:08X}    "

                hex_address_table_widget_item: QTableWidgetItem = QTableWidgetItem(address_string)
                hex_address_table_widget_item.setFont(self.monospace_font)
                buffer_hex_view.setItem(row, column, hex_address_table_widget_item)

                ascii_address_table_widget_item: QTableWidgetItem = QTableWidgetItem(address_string)
                ascii_address_table_widget_item.setFont(self.monospace_font)
                buffer_ascii_view.setItem(row, column, ascii_address_table_widget_item)

            buffer_hex_view.resizeColumnsToContents()
            buffer_ascii_view.resizeColumnsToContents()

    def packet_list_current_item_changed(self, current: QTableWidgetItem, previous: QTableWidgetItem):
        row_index: int = self.packet_list.currentIndex().row()
        if row_index < 0:
            return
        packet_id: int = self.packet_ids[row_index]
        packet: Packet = self.get_packet(packet_id)

        self.set_packet_in_packet_list(row_index, packet)
        self.set_protocol_tree(packet)
        self.set_buffer_view(packet)

    def apply_filter(self):
        self.get_packet_all_ids()
        self.clear()
        self.prepare_packet_list()
        self.set_visible_packets_in_packet_list()

        if len(self.packet_ids) >= 1:
            self.packet_list.setCurrentCell(0, 0)

    def handle_file_paths(self, file_paths: List[str]):
        self.cleanup()

        for file_path in file_paths:
            try:
                database: Connection = connect(file_path)
                self.databases.append(database)
                self.file_paths.append(file_path)
            except Exception as ex:
                show_message_box(str(ex))

        cursors: List[Cursor] = [database.cursor() for database in self.databases]

        for cursor in cursors:
            cursor.execute(f"""PRAGMA journal_mode = OFF;""")

        for cursor in cursors:
            cursor.close()

        start_time: float = time.time()
        self.apply_filter()
        end_time: float = time.time()
        duration: float = end_time - start_time
        self.info_line.setText(f"Info: Open wsdb file(s) took {duration:.2f} seconds.")

    def open_button_clicked(self):
        open_file_dialog: QFileDialog = QFileDialog()
        open_file_dialog.setFileMode(QFileDialog.AnyFile)
        file_paths, _ = QFileDialog.getOpenFileNames(self, "Open wsdb file(s)...", "",
                                                     "wsdb databases (*.wsdb);;All Files (*)")

        if file_paths is None or len(file_paths) == 0:
            return

        self.handle_file_paths(file_paths)

    def __init__(self):
        super().__init__()

        self.setWindowTitle("wsdb Browser")
        self.setGeometry(100, 100, 1280, 1024)
        self.box_layout: QVBoxLayout = QVBoxLayout()
        self.monospace_font = QFont("", 10, QFont.Monospace)
        try:
            self.monospace_font.setFamily("Consolas")
        except Exception as ex:
            self.monospace_font.setFamily("Courier New")

        self.open_button: QPushButton = QPushButton()
        self.open_button.clicked.connect(self.open_button_clicked)
        self.open_button.setText("Open wsdb file(s)...")
        self.open_button.setFont(self.monospace_font)

        self.filter_input_field_label: QLabel = QLabel()
        self.filter_input_field_label.setFont(self.monospace_font)
        self.filter_input_field_label.setText("Filter")

        self.filter_input_field: QLineEdit = QLineEdit()
        self.filter_input_field.returnPressed.connect(self.apply_filter)
        self.filter_input_field.setText("")
        self.filter_input_field.setFont(self.monospace_font)
        self.filter_input_field.setEnabled(False)

        self.packet_list_label: QLabel = QLabel()
        self.packet_list_label.setFont(self.monospace_font)
        self.packet_list_label.setText("Packet List")

        self.packet_list: MyTableWidget = MyTableWidget(self)
        self.packet_list.setColumnCount(5)
        self.packet_list.setHorizontalHeaderLabels(["Id", "Timestamp", "Length", "Protocol", "Info"])
        self.packet_list.horizontalHeader().setStretchLastSection(True)
        self.packet_list.horizontalHeader().setFont(self.monospace_font)
        self.packet_list.setFont(self.monospace_font)
        self.packet_list.currentItemChanged.connect(self.packet_list_current_item_changed)
        self.packet_list.verticalHeader().setVisible(False)
        self.packet_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.packet_list.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.packet_list.setAlternatingRowColors(True)

        self.protocol_tree_label: QLabel = QLabel()
        self.protocol_tree_label.setFont(self.monospace_font)
        self.protocol_tree_label.setText("Protocol Tree")

        self.protocol_tree: QTreeWidget = QTreeWidget()
        self.protocol_tree.setColumnCount(1)
        self.protocol_tree.setFont(self.monospace_font)
        self.protocol_tree.setHeaderLabel("")

        self.buffer_view_label: QLabel = QLabel()
        self.buffer_view_label.setFont(self.monospace_font)
        self.buffer_view_label.setText("Buffer View")

        self.buffer_view_width: int = 16
        self.buffer_view_container: QTabWidget = QTabWidget()
        self.buffer_view_container.setFont(self.monospace_font)

        self.info_line: QLabel = QLabel()
        self.info_line.setFont(self.monospace_font)
        self.info_line.setText("Info:")

        self.box_layout.addWidget(self.open_button)
        self.box_layout.addWidget(self.filter_input_field_label)
        self.box_layout.addWidget(self.filter_input_field, 1)
        self.box_layout.addWidget(self.packet_list_label)
        self.box_layout.addWidget(self.packet_list, 2)
        self.box_layout.addWidget(self.protocol_tree_label)
        self.box_layout.addWidget(self.protocol_tree, 2)
        self.box_layout.addWidget(self.buffer_view_label)
        self.box_layout.addWidget(self.buffer_view_container, 2)
        self.box_layout.addWidget(self.info_line)

        widget: QWidget = QWidget()
        widget.setLayout(self.box_layout)
        self.setCentralWidget(widget)

        self.file_paths: List[str] = []
        self.databases: List[Connection] = []
        self.packet_ids: List[int] = []

    def closeEvent(self, close_event: QCloseEvent):
        self.cleanup()
        super().closeEvent(close_event)


def main():
    app: QApplication = QApplication(sys.argv)
    window: MainWindow = MainWindow()
    window.showMaximized()
    app.exec()
    window.cleanup()
    sys.exit()


if __name__ == "__main__":
    main()
