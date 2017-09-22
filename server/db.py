import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import sessionmaker
import datetime
import yaml


class Db:

    def __init__(self, engine_string=None):
        configfile = open("./appconfig.yaml")
        self._config = yaml.load(configfile)
        if not engine_string:
            engine_string = \
                "postgresql://" \
                +config.get('username')+":" \
                +config.get('password')+"@" \
                +config.get('host')+"/" \
                +config.get('database')
        self.engine =  sa.create_engine(engine_string)
        self.Session.configure(bind=self.engine, autocommit=True)

    Session = sessionmaker()
    base = declarative_base() # Defines the base to map Tables

    class Auth_user(base):
        __tablename__ = 'auth_user'

        id = Column(Integer, primary_key=True)
        username = Column(String)
        hmac_secret = Column(String)

        def __repr__(self):
            return "<Types(username='%s', hmac_secret='%s')>" % (self.username,
                    self.hmac_secret)

    class Programs(base):
        __tablename__ = 'monitutor_programs'

        program_id = Column(Integer, primary_key=True)
        name = Column(String)
        display_name = Column(String)
        code = Column(Text(length=655360))

        def __repr__(self):
            return "<Commands(name='%s', code='%s', display_name='%s')>" % (
                self.name, self.code, self.display_name)
