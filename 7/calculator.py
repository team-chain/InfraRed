"""아이폰 스타일 계산기.

Calculator 클래스(연산 코어) + CalculatorUI 위젯(PyQt5)을 한 파일에 담았다.
PEP 8 스타일을 준수하며, 외부 라이브러리는 PyQt5만 사용한다.
"""

import sys

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QApplication,
    QGridLayout,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class Calculator:
    """계산기의 핵심 연산을 담당하는 클래스 (UI와 무관)."""

    # 처리 가능한 숫자 범위 한계 (float 한계 근방)
    MAX_VALUE = 1e308
    # 소수점 반올림 자릿수 (보너스 과제)
    DECIMAL_PLACES = 6

    def __init__(self):
        self.reset()

    # ------------------------------------------------------------------
    # 상태 제어
    # ------------------------------------------------------------------
    def reset(self):
        """모든 상태를 초기화한다."""
        self.current = '0'
        self.previous = None
        self.operator = None
        # True 이면 다음 숫자 입력 시 화면을 새로 시작한다.
        self.start_new = False

    def negative_positive(self):
        """현재 표시 값의 부호를 토글한다."""
        if self.current in ('Error', 'Overflow'):
            return self.current
        if self.current.startswith('-'):
            self.current = self.current[1:]
        elif self.current != '0':
            self.current = '-' + self.current
        return self.current

    def percent(self):
        """현재 표시 값을 100으로 나눈다."""
        if self.current in ('Error', 'Overflow'):
            return self.current
        try:
            value = float(self.current) / 100
            self.current = self._format_number(value)
        except (ValueError, OverflowError):
            self.current = 'Error'
        return self.current

    # ------------------------------------------------------------------
    # 사칙 연산
    # ------------------------------------------------------------------
    def add(self, a, b):
        return a + b

    def subtract(self, a, b):
        return a - b

    def multiply(self, a, b):
        return a * b

    def divide(self, a, b):
        if b == 0:
            raise ZeroDivisionError('0으로 나눌 수 없습니다')
        return a / b

    # ------------------------------------------------------------------
    # 입력 처리
    # ------------------------------------------------------------------
    def input_digit(self, digit):
        """숫자 키 입력. 누를 때마다 화면에 누적한다."""
        if self.current in ('Error', 'Overflow'):
            self.reset()
        if self.start_new:
            self.current = '0'
            self.start_new = False
        if self.current == '0':
            self.current = digit
        elif self.current == '-0':
            self.current = '-' + digit
        else:
            # 너무 길어지는 입력 차단 (한 줄에 표시 가능한 길이로 제한)
            if len(self.current.lstrip('-').replace('.', '')) >= 16:
                return self.current
            self.current += digit
        return self.current

    def input_dot(self):
        """소수점 입력. 이미 있으면 무시한다."""
        if self.current in ('Error', 'Overflow'):
            self.reset()
        if self.start_new:
            self.current = '0'
            self.start_new = False
        if '.' not in self.current:
            self.current += '.'
        return self.current

    def set_operator(self, op):
        """연산자 키 입력."""
        if self.current in ('Error', 'Overflow'):
            return self.current
        # 직전 입력이 숫자였다면, 누적된 연산을 먼저 처리한다.
        if (
            self.previous is not None
            and self.operator is not None
            and not self.start_new
        ):
            self.equal()
            if self.current in ('Error', 'Overflow'):
                return self.current
        try:
            self.previous = float(self.current)
        except ValueError:
            self.current = 'Error'
            return self.current
        self.operator = op
        self.start_new = True
        return self.current

    def equal(self):
        """= 키. 누적된 연산 결과를 계산해 화면에 표시한다."""
        if self.current in ('Error', 'Overflow'):
            return self.current
        if self.previous is None or self.operator is None:
            return self.current
        try:
            a = self.previous
            b = float(self.current)
            if self.operator == '+':
                result = self.add(a, b)
            elif self.operator == '-':
                result = self.subtract(a, b)
            elif self.operator == '*':
                result = self.multiply(a, b)
            elif self.operator == '/':
                result = self.divide(a, b)
            else:
                return self.current

            # 오버플로우 / NaN 검사
            if result != result or result == float('inf') or result == float('-inf'):
                raise OverflowError('처리 가능한 범위를 초과했습니다')
            if abs(result) > self.MAX_VALUE:
                raise OverflowError('처리 가능한 범위를 초과했습니다')

            self.current = self._format_number(result)
        except ZeroDivisionError:
            self.current = 'Error'
        except OverflowError:
            self.current = 'Overflow'
        except Exception:
            self.current = 'Error'

        self.previous = None
        self.operator = None
        self.start_new = True
        return self.current

    # ------------------------------------------------------------------
    # 헬퍼
    # ------------------------------------------------------------------
    @classmethod
    def _format_number(cls, value):
        """소수점 6자리 이하 반올림 후 문자열로 변환한다."""
        if value != value or value == float('inf') or value == float('-inf'):
            raise OverflowError
        rounded = round(value, cls.DECIMAL_PLACES)
        # 정수면 정수 표기
        if rounded == int(rounded) and abs(rounded) < 1e16:
            return str(int(rounded))
        # 불필요한 0 제거
        text = f'{rounded:.{cls.DECIMAL_PLACES}f}'.rstrip('0').rstrip('.')
        return text if text else '0'


class CalculatorUI(QWidget):
    """아이폰 스타일 계산기 UI."""

    # 화면에 표시되는 기호와 내부 연산자의 매핑 (× → *, ÷ → /)
    DISPLAY_TO_OP = {
        '+': '+',
        '-': '-',
        '×': '*',
        '÷': '/',
    }

    def __init__(self):
        super().__init__()
        self.calc = Calculator()
        # 디스플레이 폰트 사이즈 자동 조정용 기준값
        self._base_font_size = 70
        # 화면에 함께 보여줄 '왼쪽 피연산자'와 '연산자 기호'
        # (연산자가 눌렸을 때만 값이 채워진다)
        self._operand_text = ''
        self._operator_symbol = ''
        self.init_ui()

    # ------------------------------------------------------------------
    # UI 구성
    # ------------------------------------------------------------------
    def init_ui(self):
        """계산기 화면의 외형과 배치를 정의하는 핵심 함수."""
        self.setWindowTitle('아이폰 계산기')
        self.setFixedSize(350, 500)
        self.setStyleSheet('background-color: black;')

        # [메인 수직 레이아웃] 화면 상단(숫자창)과 하단(버튼들)을 세로로 배치한다.
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(12)

        # [숫자 표시창]
        self.display = QLineEdit('0')
        self.display.setAlignment(Qt.AlignRight)
        self.display.setReadOnly(True)
        self._apply_display_style(self._base_font_size)
        main_layout.addWidget(self.display)

        # [버튼 그리드 레이아웃] 버튼들을 바둑판(행/열) 형태로 배치한다.
        grid_layout = QGridLayout()
        grid_layout.setSpacing(12)

        # 버튼 데이터: (라벨, 타입). 타입 0=기능, 1=숫자, 2=연산
        buttons = [
            [('AC', 0), ('+/-', 0), ('%', 0), ('÷', 2)],
            [('7', 1), ('8', 1), ('9', 1), ('×', 2)],
            [('4', 1), ('5', 1), ('6', 1), ('-', 2)],
            [('1', 1), ('2', 1), ('3', 1), ('+', 2)],
        ]

        for row, row_buttons in enumerate(buttons):
            for col, (text, btn_type) in enumerate(row_buttons):
                button = QPushButton(text)
                self.style_button(button, btn_type)
                button.clicked.connect(self.button_clicked)
                grid_layout.addWidget(button, row, col)

        # [특수: '0' 버튼은 가로 두 칸을 차지한다]
        btn_0 = QPushButton('0')
        self.style_button(btn_0, 1)
        btn_0.setFixedSize(152, 70)
        btn_0.clicked.connect(self.button_clicked)
        grid_layout.addWidget(btn_0, 4, 0, 1, 2)

        # [소수점 버튼]
        btn_dot = QPushButton('.')
        self.style_button(btn_dot, 1)
        btn_dot.clicked.connect(self.button_clicked)
        grid_layout.addWidget(btn_dot, 4, 2)

        # [등호 버튼]
        btn_eq = QPushButton('=')
        self.style_button(btn_eq, 2)
        btn_eq.clicked.connect(self.button_clicked)
        grid_layout.addWidget(btn_eq, 4, 3)

        main_layout.addLayout(grid_layout)
        self.setLayout(main_layout)

    def style_button(self, button, btn_type):
        """버튼에 iOS 감성의 CSS 스타일을 입히는 함수."""
        button.setFixedSize(70, 70)
        base_style = 'border-radius: 35px; font-size: 25px; font-weight: bold;'

        if btn_type == 0:    # 상단 AC, +/-, %
            style = base_style + 'background-color: #A5A5A5; color: black;'
        elif btn_type == 1:  # 숫자 및 소수점
            style = base_style + 'background-color: #333333; color: white;'
        else:                # 사칙연산
            style = base_style + 'background-color: #FF9F0A; color: white; font-size: 30px;'

        button.setStyleSheet(style)

    def _apply_display_style(self, font_size):
        """디스플레이 스타일시트를 적용한다 (폰트 사이즈 가변)."""
        self.display.setStyleSheet(
            'border: none;'
            'color: white;'
            'background-color: black;'
            f'font-size: {font_size}px;'
            'font-weight: 300;'
            'padding-bottom: 10px;'
        )

    # ------------------------------------------------------------------
    # 이벤트
    # ------------------------------------------------------------------
    def button_clicked(self):
        """버튼 클릭 시 Calculator 클래스로 동작을 위임한다."""
        sender = self.sender()
        text = sender.text()

        if text == 'AC':
            self.calc.reset()
            self._operand_text = ''
            self._operator_symbol = ''
        elif text == '=':
            self.calc.equal()
            # 결과만 보이도록 표시용 prefix 제거
            self._operand_text = ''
            self._operator_symbol = ''
        elif text == '+/-':
            self.calc.negative_positive()
        elif text == '%':
            self.calc.percent()
            # 퍼센트 결과만 깔끔하게 보여주기 위해 prefix 제거
            self._operand_text = ''
            self._operator_symbol = ''
        elif text in self.DISPLAY_TO_OP:
            self.calc.set_operator(self.DISPLAY_TO_OP[text])
            # 체인 계산이 있었다면 calc.current 가 결과로 갱신된 상태.
            # 화면에는 "<왼쪽피연산자> <연산자>" 형태로 표시한다.
            if self.calc.current not in ('Error', 'Overflow'):
                self._operand_text = self.calc.current
                self._operator_symbol = text
            else:
                self._operand_text = ''
                self._operator_symbol = ''
        elif text == '.':
            self.calc.input_dot()
        elif text.isdigit():
            self.calc.input_digit(text)

        self._update_display()

    def _update_display(self):
        """Calculator의 현재 값을 화면에 반영하고 폰트 사이즈를 조정한다."""
        if self.calc.current in ('Error', 'Overflow'):
            text = self.calc.current
        elif self._operator_symbol:
            # 연산자가 마지막에 눌린 상태이거나 그 이후 숫자 입력 중
            if self.calc.start_new:
                # 연산자 직후 — 다음 숫자가 아직 안 들어옴
                text = f'{self._operand_text} {self._operator_symbol}'
            else:
                # 다음 숫자 입력 중
                text = (
                    f'{self._operand_text} {self._operator_symbol} '
                    f'{self.calc.current}'
                )
        else:
            text = self.calc.current
        self.display.setText(text)
        self._adjust_font_size(text)

    def _adjust_font_size(self, text):
        """보너스 과제: 표시 길이에 따라 폰트 크기를 조정한다."""
        length = len(text)
        if length <= 7:
            size = self._base_font_size  # 70
        elif length <= 9:
            size = 56
        elif length <= 12:
            size = 44
        elif length <= 16:
            size = 34
        else:
            size = 26
        self._apply_display_style(size)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    calc = CalculatorUI()
    calc.show()
    sys.exit(app.exec_())
