FROM python:3.9.12

WORKDIR /bot

COPY requirements.txt requirements.txt

RUN pip install --no-cache-dir --upgrade -r requirements.txt

COPY . /bot

CMD ["python", "kv_ptStartBot.py"]
