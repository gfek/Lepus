from sqlalchemy.orm import sessionmaker
from sqlalchemy_utils import IPAddressType
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String, Integer, create_engine

Base = declarative_base()


class Wildcard(Base):
	__tablename__ = 'wildcards'
	subdomain = Column(String(100), primary_key=True)
	domain = Column(String(100), primary_key=True)
	address = Column(IPAddressType, primary_key=True)
	timestamp = Column(Integer, nullable = False)


class Resolution(Base):
	__tablename__ = 'resolutions'
	subdomain = Column(String(100), primary_key=True)
	domain = Column(String(100), primary_key=True)
	address = Column(IPAddressType, nullable=False)
	source = Column(String(20), nullable=False)
	timestamp = Column(Integer, nullable = False)


def init():
	engine = create_engine("sqlite:///findings.sqlite")
	Base.metadata.create_all(engine)
	Base.metadata.bind = engine
	DBSession = sessionmaker(bind=engine)
	session = DBSession()

	return session
