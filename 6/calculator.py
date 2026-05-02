import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QGridLayout, QPushButton, QLineEdit
from PyQt5.QtCore import Qt

class Calculator(QWidget):
    def __init__(self):
        super().__init__()
        # 내부 메모리: 사용자가 누른 숫자와 연산자를 문자열 형태로 저장합니다.
        self.current_text = ''
        self.init_ui()

    def init_ui(self):
        """계산기 화면의 외형과 배치를 정의하는 핵심 함수"""
        self.setWindowTitle('아이폰 계산기')
        self.setFixedSize(350, 500)             # 창 크기를 고정하여 레이아웃이 깨지지 않게 함
        self.setStyleSheet("background-color: black;")  # 아이폰 계산기 특유의 검은 배경색

        # [메인 수직 레이아웃] 화면 상단(숫자창)과 하단(버튼들)을 세로로 배치합니다.
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)  # 창 테두리와 내용물 사이의 여백
        main_layout.setSpacing(12)                      # 숫자창과 버튼 그룹 사이의 간격

        # [숫자 표시창 (QLineEdit)]
        self.display = QLineEdit('0')                   # 기본값은 '0'
        self.display.setAlignment(Qt.AlignRight)        # 숫자가 오른쪽 끝에 붙도록 설정
        self.display.setReadOnly(True)                  # 사용자가 직접 타이핑하는 것을 막음
        self.display.setStyleSheet("""
            border: none;                               /* 외곽선 제거 */
            color: white;                               /* 숫자 색상은 흰색 */
            background-color: black;                    /* 배경은 검은색 */
            font-size: 70px;                            /* 아이폰처럼 아주 큰 글씨 */
            font-weight: 300;                           /* 얇고 세련된 글씨체 */
            padding-bottom: 10px;                       /* 아래쪽 버튼들과의 간격 */
        """)
        main_layout.addWidget(self.display)
      
        # [버튼 그리드 레이아웃] 버튼들을 바둑판(행/열) 형태로 배치합니다.
        grid_layout = QGridLayout()
        grid_layout.setSpacing(12)                      # 버튼과 버튼 사이의 간격 (아이폰 느낌)
        
        # 버튼 데이터 리스트: (라벨, 버튼타입)
        # 타입별 색상: 0(기능/밝은회색), 1(숫자/진회색), 2(연산/오렌지)
        buttons = [
            [('AC', 0), ('+/-', 0), ('%', 0), ('÷', 2)],
            [('7', 1), ('8', 1), ('9', 1), ('×', 2)],
            [('4', 1), ('5', 1), ('6', 1), ('-', 2)],
            [('1', 1), ('2', 1), ('3', 1), ('+', 2)]
        ]
      
        # 2중 반복문을 통해 위 리스트에 있는 버튼들을 자동으로 생성하고 배치합니다.
        for row, row_buttons in enumerate(buttons):
            for col, (text, btn_type) in enumerate(row_buttons):
                button = QPushButton(text)
                self.style_button(button, btn_type)      # 디자인 입히기
                button.clicked.connect(self.button_clicked) # 클릭 시 작동할 함수 연결
                grid_layout.addWidget(button, row, col)  # 해당 좌표에 버튼 배치
     
        # [특수 버튼 처리: '0' 버튼]
        # 0번 버튼은 가로로 두 칸을 차지해야 하므로 별도로 처리합니다.
        btn_0 = QPushButton('0')
        self.style_button(btn_0, 1)
        btn_0.setFixedSize(152, 70)                     # 가로 길이를 약 2배로 설정
        btn_0.clicked.connect(self.button_clicked)
        # addWidget(위젯, 행, 열, 행점유수, 열점유수) -> 4행 0열부터 시작해 1행 2열만큼 차지함
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

        main_layout.addLayout(grid_layout)               # 메인 레이아웃에 그리드 레이아웃 합치기
        self.setLayout(main_layout)                      # 최종 레이아웃을 창에 적용

    def style_button(self, button, btn_type):
        """버튼에 iOS 감성의 CSS 스타일을 입히는 함수"""
        button.setFixedSize(70, 70)                     # 모든 버튼은 기본적으로 정원형(70x70)
        
        # 모든 버튼 공통: border-radius를 35px로 주면 완벽한 원이 됩니다.
        base_style = "border-radius: 35px; font-size: 25px; font-weight: bold;"
        
        if btn_type == 0:   # 상단 AC, +/-, % 버튼 
            style = base_style + "background-color: #A5A5A5; color: black;"
        elif btn_type == 1: # 숫자 및 소수점 버튼 
            style = base_style + "background-color: #333333; color: white;"
        else:               # 우측 사칙연산 버튼
            style = base_style + "background-color: #FF9F0A; color: white; font-size: 30px;"
            
        button.setStyleSheet(style)

    def button_clicked(self):
        """사용자가 버튼을 클릭했을 때의 동작을 정의 (핵심 로직)"""
        sender = self.sender()                          # 클릭 이벤트를 발생시킨 버튼 객체를 가져옴
        text = sender.text()                            # 버튼에 적힌 글자(예: "7", "+", "AC")

        if text == 'AC':
            # 초기화: 내부 수식 문자열을 비우고 화면을 '0'으로 변경
            self.current_text = ''
            self.display.setText('0')
            
        elif text == '=':
            # 계산 실행: 저장된 문자열 수식을 계산
            try:
                # 아이폰용 기호
                expression = self.current_text.replace('×', '*').replace('÷', '/')
                # eval(): 문자열 "1+2*3"을 실제 수학 연산 7로 바꿔주는 마법의 함수
                result = str(eval(expression))
                self.display.setText(result)            # 계산 결과 화면 표시
                self.current_text = result               # 결과값부터 이어서 계산 가능하게 저장
            except Exception:
                # 수식이 잘못되었거나(예: "5++2") 0으로 나누려 할 때 에러 처리
                self.display.setText('Error')
                self.current_text = ''
                
        elif text == '+/-':
            # 사용자가 수식을 입력하는 도중에 숫자의 성질(양수/음수)을 즉각적으로 바꿈
            if self.current_text:
                if self.current_text.startswith('-'):
                    # 이미 마이너스가 있다면? -> 첫 글자를 제외하고 나머지만 가져옴 (음수 -> 양수)
                    self.current_text = self.current_text[1:]
                else:
                    # 마이너스가 없다면? -> 맨 앞에 '-'를 붙임 (양수 -> 음수)
                    self.current_text = '-' + self.current_text
                self.display.setText(self.current_text)
                
        elif text == '%':
            # 현재 입력된 숫자를 100으로 나누어 소수점 형태로 변환
            try:
                result = str(float(self.current_text) / 100)
                self.display.setText(result)
                self.current_text = result
            except:
                pass
                
        else:
            # 숫자나 연산자 버튼이 눌린 경우: 기존 문자열 수식 뒤에 새로운 글자를 덧붙임
            if self.current_text == '0': self.current_text = ''
            self.current_text += text
            self.display.setText(self.current_text)


if __name__ == '__main__':
    app = QApplication(sys.argv)                        # PyQt5 앱 인스턴스 생성
    calc = Calculator()                                 # 계산기 창 생성
    calc.show()                                         # 창 띄우기
    sys.exit(app.exec_())                               # 앱 실행 루프 시작 