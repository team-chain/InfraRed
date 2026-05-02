import time
import json
import random


class DummySensor:
    """화성 기지의 환경 데이터를 생성하는 더미 센서 클래스"""

    def get_data(self):
        """센서로부터 무작위 환경 데이터를 가져옵니다."""
        return {
            'mars_base_internal_temperature': round(random.uniform(18.0, 24.0), 2),
            'mars_base_external_temperature': round(random.uniform(-120.0, -20.0), 2),
            'mars_base_internal_humidity': round(random.uniform(30.0, 50.0), 2),
            'mars_base_external_illuminance': round(random.uniform(0.0, 1000.0), 2),
            'mars_base_internal_co2': round(random.uniform(400.0, 1000.0), 2),
            'mars_base_internal_oxygen': round(random.uniform(19.0, 21.0), 2)
        }


class MissionComputer:
    """화성 기지의 환경 데이터를 관리하고 출력하는 미션 컴퓨터 클래스"""

    def __init__(self):
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

    def get_sensor_data(self):
        """5초마다 센서 데이터를 가져와 출력하고, 5분마다 평균값을 계산합니다."""
        print('--- Mars Mission Control System Started ---')
        print('Press Ctrl+C to stop the system.')
        
        try:
            while True:
                
                new_data = self.ds.get_data()
                self.env_values.update(new_data)
                self.history.append(new_data)

                
                json_output = json.dumps(self.env_values, indent=4)
                print(f'\n[Current Environment Data]\n{json_output}')

                
                current_time = time.time()
                if current_time - self.start_time >= 300:
                    self._display_average_values()
                    self.start_time = current_time  
                    self.history = [] 

                
                time.sleep(5)

        except KeyboardInterrupt:
            
            print('\nSystem stopped....')

    def _display_average_values(self):
        """저장된 히스토리를 바탕으로 5분 평균값을 출력합니다."""
        if not self.history:
            return

        keys = self.env_values.keys()
        averages = {}

        for key in keys:
            total = sum(data[key] for data in self.history)
            averages[key] = round(total / len(self.history), 2)

        print('\n' + '=' * 40)
        print('[5-Minute Average Environment Report]')
        print(json.dumps(averages, indent=4))
        print('=' * 40)


if __name__ == '__main__':
    
    RunComputer = MissionComputer()
    
    RunComputer.get_sensor_data()