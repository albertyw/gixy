FROM python:alpine

ADD . /src

WORKDIR /src

RUN pip install --upgrade pip setuptools wheel
RUN python3 setup.py install

ENTRYPOINT ["gixy"]
