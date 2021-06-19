import os
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String, Integer, Boolean, create_engine

Base = declarative_base()


class Record(Base):
	__tablename__ = "records"
	domain = Column(String(100), primary_key=True)
	type = Column(String(10), primary_key=True)
	value = Column(String(1000), primary_key=True)
	timestamp = Column(Integer, nullable=False)


class Wildcard(Base):
	__tablename__ = "wildcards"
	subdomain = Column(String(100), primary_key=True)
	domain = Column(String(100), primary_key=True)
	address = Column(String(40), primary_key=True)
	timestamp = Column(Integer, nullable=False)


class Resolution(Base):
	__tablename__ = "resolutions"
	subdomain = Column(String(100), primary_key=True)
	domain = Column(String(100), primary_key=True)
	address = Column(String(40), primary_key=True)
	isWildcard = Column(Boolean, nullable=False)
	source = Column(String(20), nullable=False)
	timestamp = Column(Integer, nullable=False)


class Unresolved(Base):
	__tablename__ = "unresolved"
	subdomain = Column(String(100), primary_key=True)
	domain = Column(String(100), primary_key=True)
	timestamp = Column(Integer, nullable=False)


class ASN(Base):
	__tablename__ = "asn"
	domain = Column(String(100), primary_key=True)
	id = Column(Integer, primary_key=True)
	prefix = Column(String(50), primary_key=True)
	description = Column(String(200), nullable=False)
	timestamp = Column(Integer, nullable=False)


class Network(Base):
	__tablename__ = "networks"
	domain = Column(String(100), primary_key=True)
	cidr = Column(String(50), primary_key=True)
	identifier = Column(String(200), nullable=False)
	country = Column(String(10), nullable=False)
	timestamp = Column(Integer, nullable=False)


class OpenPort(Base):
	__tablename__ = "open_ports"
	domain = Column(String(100), primary_key=True)
	address = Column(String(40), primary_key=True)
	port = Column(Integer, primary_key=True)
	isSSL = Column(Boolean, nullable=False)
	timestamp = Column(Integer, nullable=False)


class URL(Base):
	__tablename__ = "urls"
	url = Column(String(100), primary_key=True)
	domain = Column(String(100), nullable=False)
	timestamp = Column(Integer, nullable=False)


class Takeover(Base):
	__tablename__ = "takeovers"
	subdomain = Column(String(100), primary_key=True)
	domain = Column(String(100), primary_key=True)
	provider = Column(String(30), nullable=False)
	signature = Column(String(100), nullable=False)
	timestamp = Column(Integer, nullable=False)


def init():
	if os.path.exists("findings.sqlite"):
		os.rename("findings.sqlite", "lepusdb.sqlite")

	engine = create_engine("sqlite:///lepusdb.sqlite")
	Base.metadata.create_all(engine)
	Base.metadata.bind = engine
	DBSession = sessionmaker(bind=engine)
	session = DBSession()

	return session
