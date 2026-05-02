# 🔍 화성 기지 미션 컴퓨터: 아키텍처 및 로직 심층 분석



## 1. 모듈 임포트 및 설계 철학 (Module Imports & Philosophy)

    import time
    import json
    import random

* **`random` (환경 불확실성 모사)**
  * **도입 목적:** 화성 기지 내/외부의 가상 환경 데이터를 생성합니다.
  * **아키텍처 관점:** 센서 데이터의 불규칙성을 구현하는 '노이즈 제너레이터' 역할을 합니다. 이를 통해 시스템이 극단적인 값(Edge Case)에서도 정상적으로 데이터를 수집하고 포맷팅하는지 검증할 수 있습니다.

* **`time` (시스템 스케줄링)**
  * **도입 목적:** 5초의 지연 시간을 만들고, 5분이 경과했는지 측정합니다.
  * **아키텍처 관점:** 무한 루프 내에서 CPU 점유율이 100%로 치솟는 것을 막는 폴링(Polling) 제어기이자, 주기적인 데이터 집계(Aggregation)를 트리거하는 경량 스케줄러입니다.

* **`json` (데이터 직렬화)**
  * **도입 목적:** 수집된 데이터를 콘솔 화면에 구조화하여 출력합니다.
  * **아키텍처 관점:** 파이썬 고유의 딕셔너리 객체를 웹 표준 포맷인 JSON으로 직렬화(Serialization)합니다. 이는 추후 관제 UI를 웹으로 확장하거나, 지구로 데이터를 전송할 때 별도의 변환 작업 없이 즉시 통신 가능한 유연성을 제공합니다.

---

## 2. 객체 지향 설계와 상태 관리 (OOP & State Management)

### 2.1 `DummySensor` 클래스 (하드웨어 추상화)

* **관심사의 분리 (Separation of Concerns):** 데이터의 '생성'을 담당하는 로직을 미션 컴퓨터 본체와 완전히 분리했습니다. 훗날 실제 화성 탐사 장비가 연결되더라도, `MissionComputer` 코드는 단 한 줄도 수정할 필요 없이 이 센서 클래스만 교체(Drop-in Replacement)하면 됩니다.
* **데이터 정밀도:** `round(..., 2)`를 적용하여 모든 부동소수점 데이터를 소수점 둘째 자리까지로 통일, 시스템 전반의 데이터 일관성을 확보했습니다.

### 2.2 `MissionComputer.__init__` (초기화 및 버퍼링)

* **상태 저장소 (`env_values`):** 현재 기지의 최신 상태를 항시 유지하는 인메모리(In-memory) 상태 캐시입니다.
* **데이터 버퍼링 (`history`):** 5분 단위의 평균값을 계산하기 위해 원시 데이터(Raw Data)를 잠시 모아두는 큐(Queue) 역할을 합니다. 잦은 파일 입출력(Disk I/O)을 피하고 메모리 내에서 연산을 처리하여 속도를 높였습니다.

---

## 3. 핵심 비즈니스 로직 분석 (Core Business Logic)

### 3.1 `get_sensor_data()`: 메인 이벤트 루프
이 시스템의 심장부로, 실시간 모니터링을 지속하는 역할을 합니다.

* **딕셔너리 업데이트 (`self.env_values.update(new_data)`):** 매번 새로운 딕셔너리를 생성하지 않고, 기존 상태 객체의 값을 덮어씌워 메모리 할당 오버헤드를 줄입니다.
* **Graceful Shutdown (`try-except KeyboardInterrupt`):** 무한 루프(`while True`)를 강제로 종료(Kill)하지 않고, 관리자가 `Ctrl+C`를 입력했을 때 예외를 캐치하여 시스템이 스스로 안전하게 마무리 메시지를 띄우고 종료되도록 안전망을 구축했습니다.

### 3.2 `_display_average_values()`: 엣지 컴퓨팅 기반 전처리
단순한 출력이 아닌, 데이터를 가공하는 내부(Private) 메서드입니다.

* **대역폭 최적화 설계:** 지구와 화성 간의 통신은 매우 느리고 비용이 비쌉니다. 5초마다 발생하는 모든 데이터를 전송하는 대신, 5분(300초) 단위로 데이터를 집계(Aggregation)하여 '요약된 평균 리포트'만 만들어냅니다. 이는 제한된 환경에서의 엣지 컴퓨팅(Edge Computing) 아키텍처를 모사한 것입니다.

---

## 4. 프로그램 실행 흐름 (Execution Flow)

    if __name__ == '__main__':
        RunComputer = MissionComputer()
        RunComputer.get_sensor_data()

* **모듈 방어막:** 이 코드가 다른 스크립트에서 `import` 될 때는 실행되지 않고, 오직 메인 스크립트로 직접 실행(`python mars_mission_computer.py`)될 때만 인스턴스가 생성되도록 진입점(Entry Point)을 제어합니다.
* **인스턴스 할당:** `MissionComputer` 객체를 메모리에 올리고 초기화(`__init__`) 로직을 수행합니다.
* **루프 진입:** `get_sensor_data()`를 호출하여 스크립트가 종료될 때까지 무한 관제 모드에 돌입합니다.

## 5. 출력결과
--- Mars Mission Control System Started ---
Press Ctrl+C to stop the system.

[Current Environment Data]
{
    "mars_base_internal_temperature": 23.43,
    "mars_base_external_temperature": -82.76,
    "mars_base_internal_humidity": 34.06,
    "mars_base_external_illuminance": 735.79,
    "mars_base_internal_co2": 577.39,
    "mars_base_internal_oxygen": 21.0
}

[Current Environment Data]
{
    "mars_base_internal_temperature": 19.61,
    "mars_base_external_temperature": -61.52,
    "mars_base_internal_humidity": 35.08,
    "mars_base_external_illuminance": 760.47,
    "mars_base_internal_co2": 833.58,
    "mars_base_internal_oxygen": 19.11
}

[Current Environment Data]
{
    "mars_base_internal_temperature": 21.09,
    "mars_base_external_temperature": -32.51,
    "mars_base_internal_humidity": 49.41,
    "mars_base_external_illuminance": 429.0,
    "mars_base_internal_co2": 507.65,
    "mars_base_internal_oxygen": 19.38
}

[Current Environment Data]
{
    "mars_base_internal_temperature": 23.06,
    "mars_base_external_temperature": -54.15,
    "mars_base_internal_humidity": 40.39,
    "mars_base_external_illuminance": 819.77,
    "mars_base_internal_co2": 818.19,
    "mars_base_internal_oxygen": 20.14
}
^C
System stopped....