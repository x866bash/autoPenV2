from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    target_domain = Column(String, nullable=False, index=True)
    scan_type = Column(String, nullable=False)  # full, subdomain, port, vuln
    status = Column(String, default="pending")  # pending, running, completed, failed
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    results = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)

class ScanResult(Base):
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, nullable=False, index=True)
    tool_name = Column(String, nullable=False)
    target = Column(String, nullable=False)
    vulnerability_type = Column(String, nullable=True)
    severity = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    raw_output = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)