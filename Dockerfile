FROM python:3.6
EXPOSE 5000
COPY . /ctforge
WORKDIR /ctforge
RUN python setup.py develop
COPY ./ctforge.conf /workdir/ctforge.conf
WORKDIR /workdir
CMD ["ctforge", "run", "-H", "0.0.0.0", "-P", "5000"]
