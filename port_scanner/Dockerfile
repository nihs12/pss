FROM python:3.8-slim

# 작업 디렉토리 설정
WORKDIR /app

# 필요한 파일 복사
COPY pss.py /app/
COPY templates /app/templates/
COPY probes_list /app/probes_list/

# 필요한 패키지 설치
RUN pip install flask geoip2

# 컨테이너 포트 설정
EXPOSE 5000

# Flask 앱 실행
CMD ["python", "pss.py"]

