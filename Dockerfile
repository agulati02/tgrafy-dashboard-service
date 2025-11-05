# lightweight official image for Python 3.13
FROM python:3.13-slim

# set working directory inside container
WORKDIR /app

ENV PYTHONPATH=src

# copy the contents of current directory into the container
COPY . /app/

# install packages from PyPI
RUN pip install --no-cache-dir -r requirements.txt

# start the service
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
