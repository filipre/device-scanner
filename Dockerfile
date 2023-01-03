FROM python:3.9
RUN apt-get update && apt-get install nmap -y
WORKDIR /app
ADD requirements.txt .
RUN pip install -r requirements.txt
COPY scan.py scan.py
RUN touch scan.txt
RUN touch log.txt
CMD ["python", "scan.py"]
