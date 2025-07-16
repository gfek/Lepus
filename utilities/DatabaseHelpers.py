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


class Technology(Base):
	__tablename__ = "technologies"
	subdomain = Column(String(100), primary_key=True)
	domain = Column(String(100), primary_key=True)
	technology = Column(String(100), primary_key=True)
	timestamp = Column(Integer, nullable=False)


class SensitiveFile(Base):
	__tablename__ = "sensitive_files"
	subdomain = Column(String(100), primary_key=True)
	domain = Column(String(100), primary_key=True)
	url = Column(String(200), primary_key=True)
	timestamp = Column(Integer, nullable=False)


class Vulnerability(Base):
	__tablename__ = "vulnerabilities"
	subdomain = Column(String(100), primary_key=True)
	domain = Column(String(100), primary_key=True)
	url = Column(String(200), primary_key=True)
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

def getResolvedSubdomains(db, domain):
    subdomains = []
    for r in db.query(Resolution).filter(Resolution.domain == domain, Resolution.isWildcard == False).all():
        if r.subdomain and not r.subdomain.isspace():
            subdomains.append(r.subdomain)
    return subdomains

def getAllFindings(db, domain):
    findings = {
        "resolved_subdomains": [],
        "unresolved_subdomains": [],
        "open_ports": [],
        "asns": [],
        "networks": [],
        "takeovers": [],
        "technologies": [],
        "sensitive_files": [],
        "vulnerabilities": [],
        "urls": []
    }

    for r in db.query(Resolution).filter(Resolution.domain == domain).all():
        findings["resolved_subdomains"].append({
            "subdomain": r.subdomain,
            "address": r.address,
            "isWildcard": r.isWildcard,
            "source": r.source
        })

    for u in db.query(Unresolved).filter(Unresolved.domain == domain).all():
        findings["unresolved_subdomains"].append({
            "subdomain": u.subdomain
        })

    for op in db.query(OpenPort).filter(OpenPort.domain == domain).all():
        findings["open_ports"].append({
            "subdomain": op.domain,
            "address": op.address,
            "port": op.port,
            "isSSL": op.isSSL
        })

    for a in db.query(ASN).filter(ASN.domain == domain).all():
        findings["asns"].append({
            "id": a.id,
            "prefix": a.prefix,
            "description": a.description
        })

    for n in db.query(Network).filter(Network.domain == domain).all():
        findings["networks"].append({
            "cidr": n.cidr,
            "identifier": n.identifier,
            "country": n.country
        })

    for t in db.query(Takeover).filter(Takeover.domain == domain).all():
        findings["takeovers"].append({
            "subdomain": t.subdomain,
            "provider": t.provider,
            "signature": t.signature
        })

    for tech in db.query(Technology).filter(Technology.domain == domain).all():
        findings["technologies"].append({
            "subdomain": tech.subdomain,
            "technology": tech.technology
        })

    for sf in db.query(SensitiveFile).filter(SensitiveFile.domain == domain).all():
        findings["sensitive_files"].append({
            "subdomain": sf.subdomain,
            "url": sf.url
        })

    for vuln in db.query(Vulnerability).filter(Vulnerability.domain == domain).all():
        findings["vulnerabilities"].append({
            "subdomain": vuln.subdomain,
            "url": vuln.url
        })

    for u in db.query(URL).filter(URL.domain == domain).all():
        findings["urls"].append({
            "url": u.url
        })

    return findings
