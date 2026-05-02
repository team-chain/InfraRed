import time
import json
import random
import platform
import psutil  #  시스템 정보를 가져오기 위한 외부 라이브러리


class DummySensor:
    """
     화성 기지의 환경 데이터를 무작위로 생성하는 더미 센서 클래스
    """

    def get_data(self):
        """센서로부터 무작위 환경 데이터를 딕셔너리 형태로 반환합니다."""
        return {
            'mars_base_internal_temperature': round(random.uniform(18.0, 24.0), 2),
            'mars_base_external_temperature': round(random.uniform(-120.0, -20.0), 2),
            'mars_base_internal_humidity': round(random.uniform(30.0, 50.0), 2),
            'mars_base_external_illuminance': round(random.uniform(0.0, 1000.0), 2),
            'mars_base_internal_co2': round(random.uniform(400.0, 1000.0), 2),
            'mars_base_internal_oxygen': round(random.uniform(19.0, 21.0), 2)
        }


class MissionComputer:
    """
    화성 기지의 환경 데이터를 관리하고 시스템 상태를 모니터링하는 메인 클래스
    """

    def __init__(self):
        # 센서 데이터 초기화 및 측정 기록용 변수 세팅
        self.env_values = {
            'mars_base_internal_temperature': 0.0,
            'mars_base_external_temperature': 0.0,
            'mars_base_internal_humidity': 0.0,
            'mars_base_external_illuminance': 0.0,
            'mars_base_internal_co2': 0.0,
            'mars_base_internal_oxygen': 0.0
        }
        self.ds = DummySensor()
        self.history = []
        self.start_time = time.time()

    def _read_settings(self):
        """
        [보너스 과제] setting.txt 파일을 읽어 출력할 항목 리스트를 반환합니다.
        파일이 없거나 읽기 오류가 발생하면 빈 리스트를 반환하여 프로그램 다운을 방지합니다.
        """
        try:
            with open('setting.txt', 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return []
        except Exception as e:
            print(f'설정 파일 오류: {e}')
            return []

    def _filter_data(self, data, settings):
        """
        [보너스 과제] 시스템 정보 딕셔너리에서 setting.txt에 명시된 항목만 남깁니다.
        """
        if not settings:  # 필터링 조건이 없으면 전체 데이터 반환
            return data
        
        filtered = {}
        for key in settings:
            if key in data:
                filtered[key] = data[key]
        return filtered

    def get_mission_computer_info(self):
        """
        [Task 8] 미션 컴퓨터의 정적 시스템 정보(OS, CPU, 메모리)를 수집합니다.
        [제약조건] 시스템 정보를 가져오는 부분은 예외처리가 되어 있어야 합니다.
        """
        try:
            # 전체 메모리 바이트를 GB 단위로 변환 후 소수점 2자리 반올림
            mem_size_gb = psutil.virtual_memory().total / (1024 ** 3)
            
            #  운영체계, 버전, CPU 타입, 코어 수, 메모리 크기 수집
            system_info = {
                'os': platform.system(),
                'os_version': platform.version(),
                'cpu_type': platform.processor() or platform.machine(),
                'cpu_cores': psutil.cpu_count(logical=False),
                'memory_size_gb': round(mem_size_gb, 2)
            }
            
            # [보너스 과제] 설정된 항목만 필터링
            settings = self._read_settings()
            filtered_info = self._filter_data(system_info, settings)
            
            # 결과를 JSON 형식으로 출력 (단일 따옴표 및 공백 규정 준수)
            return json.dumps(filtered_info, indent=4, ensure_ascii=False)
            
        except Exception as e:
            error_data = {'error': f'시스템 정보 수집 실패: {e}'}
            return json.dumps(error_data, ensure_ascii=False)

    def get_mission_computer_load(self):
        """
        미션 컴퓨터의 실시간 부하(CPU, 메모리 사용량)를 수집합니다.
        [제약조건] 예외 처리가 반영되어 있습니다.
        """
        try:
            #  CPU 실시간 사용량, 메모리 실시간 사용량
            load_info = {
                'cpu_usage_percent': psutil.cpu_percent(interval=1.0),
                'memory_usage_percent': psutil.virtual_memory().percent
            }
            
            # [보너스 과제] 설정된 항목만 필터링
            settings = self._read_settings()
            filtered_load = self._filter_data(load_info, settings)
            
            # [요구사항] 결과를 JSON 형식으로 출력
            return json.dumps(filtered_load, indent=4, ensure_ascii=False)
            
        except Exception as e:
            error_data = {'error': f'시스템 부하 수집 실패: {e}'}
            return json.dumps(error_data, ensure_ascii=False)

    def get_sensor_data(self):
        """
         5초마다 환경 데이터를 수집하여 출력하고, 5분(300초)마다 평균값을 산출합니다.
        """
        print('\n--- Mars Mission Control System Started ---')
        
        try:
            while True:  # 5초 간격 무한 루프
                # 센서 데이터 수집 및 업데이트
                new_data = self.ds.get_data()
                self.env_values.update(new_data)
                self.history.append(new_data)

                # 현재 데이터를 JSON 형태로 변환하여 출력
                json_output = json.dumps(self.env_values, indent=4)
                print(f'\n[Current Environment Data]\n{json_output}')

                # 5분(300초)이 경과했는지 확인
                current_time = time.time()
                if current_time - self.start_time >= 300:
                    self._display_average_values()
                    self.start_time = current_time  # 기준 시간 초기화
                    self.history = []               # 누적 데이터 초기화

                # 5초 대기
                time.sleep(5)

        except KeyboardInterrupt:
            # Ctrl+C 입력 시 안전하게 루프 종료
            print('\nSystem stopped....')

    def _display_average_values(self):
        """
         history에 누적된 환경 데이터들의 평균을 계산하여 화면에 출력합니다.
        """
        if not self.history:
            return

        keys = self.env_values.keys()
        averages = {}

        # 각 항목별 합계를 구하고 누적 횟수로 나누어 평균 도출
        for key in keys:
            total = sum(data[key] for data in self.history)
            averages[key] = round(total / len(self.history), 2)

        print('\n' + '=' * 40)
        print('[5-Minute Average Environment Report]')
        print(json.dumps(averages, indent=4))
        print('=' * 40)


if __name__ == '__main__':
    #  MissionComputer 클래스를 runComputer 라는 이름으로 인스턴스화 한다.
    runComputer = MissionComputer()
    
    # 메소드를 호출해서 시스템 정보에 대한 값을 출력할 수 있도록 한다.
    print('=== 시스템 정보 ===')
    print(runComputer.get_mission_computer_info())
    
    print('\n=== 시스템 부하 ===')
    print(runComputer.get_mission_computer_load())
    
    #  기존 환경 데이터 모니터링 무한 루프 시작
    runComputer.get_sensor_data()