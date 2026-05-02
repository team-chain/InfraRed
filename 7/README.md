# 계산기 (Calculator)

아이폰 스타일의 GUI 계산기. 연산 로직을 담당하는 `Calculator` 클래스와 PyQt5 기반 UI를 한 파일(`calculator.py`)에 담았다.

## 요구 환경

- Python 3.x
- PyQt5 (UI 전용, 그 외 외부 라이브러리는 사용하지 않음)

```bash
pip install PyQt5
python3 calculator.py
```

---

## 수행과제별 구현 설명

### 1. Calculator 클래스를 만든다

연산 로직을 UI와 분리해서 순수 클래스로 만들었다. 상태로 현재 표시 값(`current`), 직전 피연산자(`previous`), 대기 중 연산자(`operator`), 그리고 다음 숫자 입력 시 화면을 새로 시작할지 여부(`start_new`)를 가진다. 생성자에서 `reset()`을 호출해 깨끗한 상태로 출발한다.

```python
class Calculator:
    """계산기의 핵심 연산을 담당하는 클래스 (UI와 무관)."""

    # 처리 가능한 숫자 범위 한계 (float 한계 근방)
    MAX_VALUE = 1e308
    # 소수점 반올림 자릿수 (보너스 과제)
    DECIMAL_PLACES = 6

    def __init__(self):
        self.reset()
```

---

### 2. 사칙연산 메소드 — `add()`, `subtract()`, `multiply()`, `divide()`

각각 두 인자를 받아 결과를 돌려주는 단순한 함수다. 단, `divide()`는 0으로 나누는 경우 `ZeroDivisionError`를 발생시켜, 호출 측에서 잡아 화면에 `Error`로 표시할 수 있게 했다 (제약조건: "0을 나누면 안된다").

```python
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
```

---

### 3. 보조 메소드 — `reset()`, `negative_positive()`, `percent()`

- `reset()` — 모든 상태값을 초기 상태로 되돌린다 (AC 키 동작).
- `negative_positive()` — 표시 값의 부호 토글. `'0'`은 토글해도 의미가 없으므로 그대로 두고, 음수 부호가 있으면 떼고 없으면 붙인다.
- `percent()` — 현재 값을 100으로 나눈다. 결과는 `_format_number()`를 거쳐 깔끔하게 표시된다.

> 과제 명세의 메소드 이름 `negative-positive`는 파이썬 식별자에 하이픈을 쓸 수 없어 PEP 8에 맞춰 `negative_positive`로 표기한다.

```python
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
```

---

### 4. 숫자키를 누를 때마다 화면에 숫자가 누적된다

`input_digit()`이 누를 때마다 `current` 문자열에 해당 숫자를 이어 붙인다. 첫 자리 `'0'`은 새 숫자로 대체되고, 너무 길어지면(16자리 초과) 입력을 차단한다. 또한 `Error`/`Overflow` 상태에서 숫자를 누르면 자동으로 `reset()` 후 새 입력으로 시작한다.

```python
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
```

---

### 5. 소수점 키 — 이미 입력되어 있으면 추가 입력되지 않음

`'.' not in self.current` 가드로 두 번째 소수점 입력을 차단한다. 즉 `1.2`인 상태에서 `.`을 또 눌러도 `1.2`가 그대로 유지된다.

```python
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
```

---

### 6. `equal()` 메소드 — 결과 출력

저장된 `previous`(왼쪽 피연산자)와 `current`(오른쪽 피연산자), `operator`를 기반으로 사칙연산 메소드를 호출해 결과를 만든다. 발생할 수 있는 모든 수학 예외(0 나누기, 오버플로우, NaN, 무한대)를 `try/except`로 잡아 `Error` 또는 `Overflow` 문자열로 화면에 표시한다.

또한 `set_operator()`는 연산자가 연속으로 들어오는 경우(예: `2 + 3 + 4`) 가운데 `+`에서 누적된 `2 + 3`을 먼저 `equal()`로 처리해, 자연스러운 체인 계산을 지원한다.

```python
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
```

---

### 7. UI 버튼과 Calculator 클래스 연결 — 완전한 동작 구현

모든 버튼의 `clicked` 시그널은 단일 핸들러 `button_clicked()`로 모인다. 핸들러는 버튼 텍스트에 따라 `Calculator`의 적절한 메소드로 분기한 뒤, 마지막에 `_update_display()`로 화면을 갱신한다. 화면 기호(`×`, `÷`)는 내부 연산자(`*`, `/`)로 변환된다.

```python
    # 화면에 표시되는 기호와 내부 연산자의 매핑 (× → *, ÷ → /)
    DISPLAY_TO_OP = {
        '+': '+',
        '-': '-',
        '×': '*',
        '÷': '/',
    }

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
            self._operand_text = ''
            self._operator_symbol = ''
        elif text == '+/-':
            self.calc.negative_positive()
        elif text == '%':
            self.calc.percent()
            self._operand_text = ''
            self._operator_symbol = ''
        elif text in self.DISPLAY_TO_OP:
            self.calc.set_operator(self.DISPLAY_TO_OP[text])
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
```

각 버튼은 `init_ui()`에서 그리드에 배치되며, 동일한 슬롯에 연결된다.

```python
        for row, row_buttons in enumerate(buttons):
            for col, (text, btn_type) in enumerate(row_buttons):
                button = QPushButton(text)
                self.style_button(button, btn_type)
                button.clicked.connect(self.button_clicked)
                grid_layout.addWidget(button, row, col)
```

---

## 보너스 과제

### B-1. 출력 길이에 따라 폰트 크기 자동 조정

`_adjust_font_size()`가 표시 문자열 길이에 따라 5단계로 폰트 크기를 줄여, 긴 결과도 한 줄에 들어오게 한다. 길이별 매핑은 7자 이하부터 17자 이상까지 단계적으로 떨어진다.

```python
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
```

`_update_display()`는 매번 화면을 그릴 때마다 이 함수를 호출해 폰트를 다시 맞춘다.

```python
    def _update_display(self):
        """Calculator의 현재 값을 화면에 반영하고 폰트 사이즈를 조정한다."""
        if self.calc.current in ('Error', 'Overflow'):
            text = self.calc.current
        elif self._operator_symbol:
            if self.calc.start_new:
                text = f'{self._operand_text} {self._operator_symbol}'
            else:
                text = (
                    f'{self._operand_text} {self._operator_symbol} '
                    f'{self.calc.current}'
                )
        else:
            text = self.calc.current
        self.display.setText(text)
        self._adjust_font_size(text)
```

---

### B-2. 소수점 6자리 이하 반올림 출력

`_format_number()`가 모든 계산 결과를 `round(value, 6)`으로 반올림한 뒤 문자열로 변환한다. 결과가 정수면 정수 표기(`8`), 소수면 끝의 불필요한 `0`을 제거한 표기(`0.333333`)로 다듬는다. NaN/무한대는 `OverflowError`로 처리된다.

```python
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
```

---

## 예외 처리 요약 (제약조건 대응)

| 상황 | 처리 |
| --- | --- |
| 0으로 나누기 | `divide()`가 `ZeroDivisionError` 발생 → `equal()`이 잡아 `Error` 표시 |
| 처리 범위 초과 (`±inf`, `NaN`, `1e308` 초과) | `OverflowError`로 처리 → `Overflow` 표시 |
| 에러 상태에서 숫자/소수점 입력 | 자동 `reset()` 후 새 입력 시작 |
| 소수점 중복 입력 | `'.' not in self.current` 가드로 무시 |
| 과도하게 긴 입력 | 16자리 초과 시 누적 중단 |

---

## 사용 예

| 입력 | 결과 |
| --- | --- |
| `12 + 7 =` | `19` |
| `5 - 8 =` | `-3` |
| `6 × 7 =` | `42` |
| `9 ÷ 4 =` | `2.25` |
| `5 ÷ 0 =` | `Error` |
| `2 + 3 + 4 =` | `9` (체인 계산) |
| `50 %` | `0.5` |
| `1 ÷ 3 =` | `0.333333` (6자리 반올림) |
| `5 +/- +/-` | `5` |

---

## 코딩 스타일

- PEP 8 준수
- 문자열은 작은따옴표(`'`)를 기본으로 사용
- 대입문 `=` 앞뒤 공백
- 들여쓰기는 공백 4칸
- 외부 라이브러리는 UI용 `PyQt5`만 사용 (그 외는 모두 파이썬 표준 기능)
