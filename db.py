import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import sessionmaker
import datetime
import yaml

configfile = open("./appconfig.yaml")
config = yaml.load(configfile)


engine = sa.create_engine("postgresql://"+config.get('username')+":"+config.get('password')+"@localhost/"+config.get('database'))
Base = declarative_base() # Defines the base to map Tables

class Auth_user(Base):
    __tablename__ = 'auth_user'

    id = Column(Integer, primary_key=True)
    username = Column(String)
    hmac_secret = Column(String)

    def __repr__(self):
        return "<Types(username='%s', hmac_secret='%s')>" % (self.username,
                self.hmac_secret)

class Check_tasks(Base):
    __tablename__ = 'monitutor_check_tasks'

    check_tasks_id = Column(Integer, primary_key=True)
    username = Column(String)
    hostname = Column(String)
    interpreter_path = Column(String)
    prio = Column(Integer)
    status = Column(String)
    check_name = Column(String)
    timestamp = Column(DateTime)
    parameters = Column(String)
    program_name = Column(String)

    def __repr__(self):
        return "<Types(prio='%s', username='%s', hostname='%s', check_name='%s', parameters='%s'," \
               " interpreter_path='%s', status='%s', timestamp='%s')>" % (self.prio, self.username, self.hostname,
                                                                          self.check_name, self.parameters,
                                                                          self.interpreter_path, self.status,
                                                                          self.timestamp)


class Checks(Base):
    __tablename__ = 'monitutor_checks'

    check_id = Column(Integer, primary_key=True)
    name = Column(String)
    display_name = Column(DateTime)
    params = Column(String)
    hint = Column(String)
    program_id = Column(Integer, ForeignKey("programs.commandid"))

    def __repr__(self):
        return "<Checks(name='%s', display_name='%s', params='%s', hint='%s'," \
               "program_id='%s')>" % (
            self.name, self.display_name, self.params, self.hint,
            self.program_id)


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


