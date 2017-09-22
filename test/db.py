import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import sessionmaker
import datetime
import yaml

configfile = open("./appconfig.yaml")
config = yaml.load(configfile)
engine = sa.create_engine('sqlite:///:memory:', echo=False)

Base = declarative_base() # Defines the base to map Tables

class Auth_user(Base):
    __tablename__ = 'auth_user'

    id = Column(Integer, primary_key=True)
    username = Column(String)
    hmac_secret = Column(String)

    def __repr__(self):
        return "<Types(username='%s', hmac_secret='%s')>" % (self.username,
                self.hmac_secret)

class Programs(Base):
    __tablename__ = 'monitutor_programs'

    program_id = Column(Integer, primary_key=True)
    name = Column(String)
    display_name = Column(String)
    code = Column(Text(length=655360))

    def __repr__(self):
        return "<Commands(name='%s', code='%s', display_name='%s')>" % (
            self.name, self.code, self.display_name)

Session = sessionmaker(bind=engine, autocommit=True)

if "__main__" == __name__:
    session = Session()
    session.add(check2)
    session.commit()


