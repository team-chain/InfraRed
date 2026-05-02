import datetime
import random


# 수행과제 1 : 더미 센서에 해당하는 클래스를 생성한다. 클래스의 이름은 DummySensor로 정의한다.
class DummySensor:
    def __init__(self):
        # 수행과제 2 : DummySensor의 멤버로 env_values라는 사전 객체를 추가한다. 사전 객체에는 다음과 같은 항목들이 추가 되어 있어야 한다.
        self.env_values = {
            'mars_base_internal_temperature': 0.0,
            'mars_base_external_temperature': 0.0,
            'mars_base_internal_humidity': 0.0,
            'mars_base_external_illuminance': 0.0,
            'mars_base_internal_co2': 0.0,
            'mars_base_internal_oxygen': 0.0
        }

    def set_env(self):
        # 수행과제 3 : DummySensor는 테스트를 위한 객체이므로 데이터를 랜덤으로 생성한다.
        # 수행과제 4 : DummySensor 클래스에 set_env() 메소드를 추가한다. 
        # set_env() 메소드는 random으로 주어진 범위 안의 값을 생성해서 env_values 항목에 채워주는 역할을 한다. 
        self.env_values['mars_base_internal_temperature'] = round(random.uniform(18.0, 30.0), 2)
        self.env_values['mars_base_external_temperature'] = round(random.uniform(0.0, 21.0), 2)
        self.env_values['mars_base_internal_humidity'] = round(random.uniform(50.0, 60.0), 2)
        self.env_values['mars_base_external_illuminance'] = round(random.uniform(500.0, 715.0), 2)
        self.env_values['mars_base_internal_co2'] = round(random.uniform(0.02, 0.1), 4)
        self.env_values['mars_base_internal_oxygen'] = round(random.uniform(4.0, 7.0), 2)

    # 수행과제 5 : DummySensor 클래스는 get_env() 메소드를 추가하는데 get_env() 메소드는 env_values를 return 한다.
    def get_env(self):
        # [보너스 과제] 날짜와 시간 및 센서 데이터를 파일에 log로 남김
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        log_data = '날짜와시간: {}, 화성 기지 내부 온도: {}, 화성 기지 외부 온도: {}, 화성 기지 내부 습도: {}, 화성 기지 외부 광량: {}, 화성 기지 내부 이산화탄소 농도: {}, 화성 기지 내부 산소 농도: {}\n'.format(
            now,
            self.env_values['mars_base_internal_temperature'],
            self.env_values['mars_base_external_temperature'],
            self.env_values['mars_base_internal_humidity'],
            self.env_values['mars_base_external_illuminance'],
            self.env_values['mars_base_internal_co2'],
            self.env_values['mars_base_internal_oxygen']
        )
        
        
        with open('sensor_log.txt', 'a', encoding='utf-8') as f:
            f.write(log_data)
            
        return self.env_values


# 메인 실행부
if __name__ == '__main__':
    # 수행과제 6: DummySensor 클래스를 ds라는 이름으로 인스턴스(Instance)로 만든다.
    ds = DummySensor()
    
    # 수행과제 7 : 인스턴스화 한 DummySensor 클래스에서 set_env()와 get_env()를 차례로 호출해서 값을 확인한다.
    ds.set_env()
    current_env = ds.get_env()
    
    # 결과 확인 출력
    print('--- 화성 기지 환경 센서 데이터 ---')
    for key, value in current_env.items():
        print('{}: {}'.format(key, value))