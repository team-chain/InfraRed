import sys
from PyQt5.QtCore import Qt, QPoint
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QApplication,
    QFrame,
    QGridLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class Calculator(QWidget):
    def __init__(self):
        super().__init__()
        self.current_input = '0'
        self.first_number = None
        self.operator = None
        self.waiting_for_second_number = False
        self.expression_text = ''
        self.old_pos = None

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Calculator')
        self.setFixedSize(420, 860)
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)

        outer_layout = QVBoxLayout()
        outer_layout.setContentsMargins(20, 20, 20, 20)

        self.phone_body = QFrame()
        self.phone_body.setStyleSheet(
            'QFrame {'
            'background-color: #111111;'
            'border: 4px solid #010101;'
            'border-radius: 42px;'
            '}'
        )

        phone_layout = QVBoxLayout()
        phone_layout.setContentsMargins(18, 18, 18, 22)
        phone_layout.setSpacing(10)

        self.notch = QFrame()
        self.notch.setFixedSize(170, 34)
        self.notch.setStyleSheet(
            'QFrame {'
            'background-color: black;'
            'border-radius: 17px;'
            '}'
        )

        notch_wrapper = QVBoxLayout()
        notch_wrapper.setContentsMargins(0, 0, 0, 0)
        notch_wrapper.setAlignment(Qt.AlignHCenter)
        notch_wrapper.addWidget(self.notch)

        self.history_label = QLabel('')
        self.history_label.setAlignment(Qt.AlignRight | Qt.AlignBottom)
        self.history_label.setFixedHeight(48)
        self.history_label.setStyleSheet(
            'color: #9a9a9a;'
            'background-color: transparent;'
            'padding-right: 10px;'
        )
        self.history_label.setFont(QFont('Arial', 16))

        self.display = QLabel('0')
        self.display.setAlignment(Qt.AlignRight | Qt.AlignBottom)
        self.display.setFixedHeight(110)
        self.display.setStyleSheet(
            'color: white;'
            'background-color: transparent;'
            'padding-right: 10px;'
        )
        self.display.setFont(QFont('Arial', 40))

        display_wrapper = QVBoxLayout()
        display_wrapper.setContentsMargins(0, 8, 0, 8)
        display_wrapper.setSpacing(0)
        display_wrapper.addWidget(self.history_label)
        display_wrapper.addWidget(self.display)

        button_layout = QGridLayout()
        button_layout.setSpacing(12)

        buttons = [
            [('AC', 'function'), ('+/-', 'function'), ('%', 'function'), ('÷', 'operator')],
            [('7', 'number'), ('8', 'number'), ('9', 'number'), ('×', 'operator')],
            [('4', 'number'), ('5', 'number'), ('6', 'number'), ('-', 'operator')],
            [('1', 'number'), ('2', 'number'), ('3', 'number'), ('+', 'operator')],
            [('0', 'number_wide'), ('.', 'number'), ('=', 'operator')],
        ]

        for row, button_row in enumerate(buttons):
            col = 0
            for text, button_type in button_row:
                button = QPushButton(text)
                button.setFont(QFont('Arial', 20))
                button.setCursor(Qt.PointingHandCursor)
                button.clicked.connect(self.handle_button_click)

                if button_type == 'function':
                    button.setFixedSize(82, 82)
                    button.setStyleSheet(self.function_button_style())
                    button_layout.addWidget(button, row, col)
                    col += 1

                elif button_type == 'operator':
                    button.setFixedSize(82, 82)
                    button.setStyleSheet(self.operator_button_style())
                    button_layout.addWidget(button, row, col)
                    col += 1

                elif button_type == 'number':
                    button.setFixedSize(82, 82)
                    button.setStyleSheet(self.number_button_style())
                    button_layout.addWidget(button, row, col)
                    col += 1

                elif button_type == 'number_wide':
                    button.setFixedSize(176, 82)
                    button.setStyleSheet(self.zero_button_style())
                    button_layout.addWidget(button, row, col, 1, 2)
                    col += 2

        phone_layout.addLayout(notch_wrapper)
        phone_layout.addLayout(display_wrapper)
        phone_layout.addLayout(button_layout)

        self.phone_body.setLayout(phone_layout)
        outer_layout.addWidget(self.phone_body)
        self.setLayout(outer_layout)

    def number_button_style(self):
        return (
            'QPushButton {'
            'background-color: #505050;'
            'color: white;'
            'border: none;'
            'border-radius: 41px;'
            '}'
            'QPushButton:pressed {'
            'background-color: #6a6a6a;'
            '}'
        )

    def zero_button_style(self):
        return (
            'QPushButton {'
            'background-color: #505050;'
            'color: white;'
            'border: none;'
            'border-radius: 41px;'
            'text-align: left;'
            'padding-left: 30px;'
            '}'
            'QPushButton:pressed {'
            'background-color: #6a6a6a;'
            '}'
        )

    def function_button_style(self):
        return (
            'QPushButton {'
            'background-color: #d4d4d2;'
            'color: black;'
            'border: none;'
            'border-radius: 41px;'
            '}'
            'QPushButton:pressed {'
            'background-color: #ebebeb;'
            '}'
        )

    def operator_button_style(self):
        return (
            'QPushButton {'
            'background-color: #ff9f0a;'
            'color: white;'
            'border: none;'
            'border-radius: 41px;'
            '}'
            'QPushButton:pressed {'
            'background-color: #ffb340;'
            '}'
        )

    def handle_button_click(self):
        button = self.sender()
        text = button.text()

        if text.isdigit():
            self.input_number(text)
        elif text == '.':
            self.input_decimal()
        elif text == '+':
            self.set_operator('+')
        elif text == '-':
            self.set_operator('-')
        elif text == '×':
            self.set_operator('×')
        elif text == '÷':
            self.set_operator('÷')
        elif text == '=':
            self.equal()
        elif text == 'AC':
            self.reset()
        elif text == '+/-':
            self.negative_positive()
        elif text == '%':
            self.percent()

        self.update_display()

    def input_number(self, number):
        if self.current_input in ['Error', 'Overflow']:
            self.current_input = '0'

        if self.waiting_for_second_number:
            self.current_input = number
            self.waiting_for_second_number = False
            return

        if self.current_input == '0':
            self.current_input = number
        else:
            self.current_input += number

        self.check_number_length()

    def input_decimal(self):
        if self.current_input in ['Error', 'Overflow']:
            self.current_input = '0'

        if self.waiting_for_second_number:
            self.current_input = '0.'
            self.waiting_for_second_number = False
            return

        if '.' not in self.current_input:
            self.current_input += '.'

    def set_operator(self, operator):
        if self.current_input in ['Error', 'Overflow']:
            return

        if self.operator is not None and not self.waiting_for_second_number:
            self.equal()

        try:
            self.first_number = float(self.current_input)
        except ValueError:
            self.current_input = 'Error'
            return

        self.operator = operator
        self.expression_text = f'{self.format_number(self.first_number)} {operator}'
        self.waiting_for_second_number = True

    def add(self, first_number, second_number):
        return first_number + second_number

    def subtract(self, first_number, second_number):
        return first_number - second_number

    def multiply(self, first_number, second_number):
        return first_number * second_number

    def divide(self, first_number, second_number):
        if second_number == 0:
            raise ZeroDivisionError
        return first_number / second_number

    def reset(self):
        self.current_input = '0'
        self.first_number = None
        self.operator = None
        self.waiting_for_second_number = False
        self.expression_text = ''

    def negative_positive(self):
        if self.current_input in ['0', 'Error', 'Overflow']:
            return

        if self.current_input.startswith('-'):
            self.current_input = self.current_input[1:]
        else:
            self.current_input = '-' + self.current_input

    def percent(self):
        if self.current_input in ['Error', 'Overflow']:
            return

        try:
            number = float(self.current_input)
            result = number / 100
            self.current_input = self.format_number(result)
        except ValueError:
            self.current_input = 'Error'

    def equal(self):
        if self.operator is None or self.first_number is None:
            return

        try:
            second_number = float(self.current_input)
        except ValueError:
            self.current_input = 'Error'
            return

        full_expression = (
            f'{self.format_number(self.first_number)} '
            f'{self.operator} '
            f'{self.format_number(second_number)} ='
        )

        try:
            if self.operator == '+':
                result = self.add(self.first_number, second_number)
            elif self.operator == '-':
                result = self.subtract(self.first_number, second_number)
            elif self.operator == '×':
                result = self.multiply(self.first_number, second_number)
            elif self.operator == '÷':
                result = self.divide(self.first_number, second_number)
            else:
                return

            if abs(result) > 999999999999:
                self.current_input = 'Overflow'
            else:
                self.current_input = self.format_number(result)

            self.expression_text = full_expression
            self.first_number = None
            self.operator = None
            self.waiting_for_second_number = True

        except ZeroDivisionError:
            self.current_input = 'Error'
            self.expression_text = 'Cannot divide by zero'
            self.first_number = None
            self.operator = None
            self.waiting_for_second_number = True
        except OverflowError:
            self.current_input = 'Overflow'
            self.expression_text = full_expression
            self.first_number = None
            self.operator = None
            self.waiting_for_second_number = True

    def format_number(self, value):
        rounded_value = round(value, 6)

        if rounded_value == int(rounded_value):
            return str(int(rounded_value))

        return str(rounded_value)

    def check_number_length(self):
        if len(self.current_input.replace('.', '').replace('-', '')) > 12:
            self.current_input = 'Overflow'

    def update_display(self):
        self.history_label.setText(self.expression_text)
        self.display.setText(self.current_input)
        self.adjust_display_font()

    def adjust_display_font(self):
        text_length = len(self.current_input)

        if text_length <= 8:
            font_size = 40
        elif text_length <= 10:
            font_size = 34
        elif text_length <= 12:
            font_size = 28
        else:
            font_size = 22

        self.display.setFont(QFont('Arial', font_size))

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.old_pos = event.globalPos()

    def mouseMoveEvent(self, event):
        if self.old_pos is not None:
            delta = QPoint(event.globalPos() - self.old_pos)
            self.move(self.x() + delta.x(), self.y() + delta.y())
            self.old_pos = event.globalPos()

    def mouseReleaseEvent(self, event):
        self.old_pos = None


def main():
    app = QApplication(sys.argv)
    calculator = Calculator()
    calculator.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()