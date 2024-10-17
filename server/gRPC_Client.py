import grpc
import realtime_pb2
import realtime_pb2_grpc
import json
import logging
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, scoped_session, relationship, declarative_base
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime
import os
import app.config

engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
Session = scoped_session(sessionmaker(bind=engine))


Base = declarative_base()


log_file_path = 'logs/gRPC_Client.log'
os.makedirs(os.path.dirname(log_file_path), exist_ok=True)  

logging.basicConfig(
    filename=log_file_path,
    level=logging.ERROR,  
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('gRPC_Client')


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(150), nullable=False, unique=True)
    email = Column(String(150), nullable=False, unique=True)
    password = Column(String(150), nullable=False)
    keywords = relationship('Keyword', back_populates='user', lazy=True, cascade='all, delete-orphan')
    monitored_certificates = relationship('MonitoredCertificate', back_populates='user', lazy=True, cascade='all, delete-orphan')


class Keyword(Base):
    __tablename__ = 'keywords'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    keyword = Column(String(255), nullable=False)
    user = relationship('User', back_populates='keywords')

class MonitoredCertificate(Base):
    __tablename__ = 'monitored_certificates'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    certificate_id = Column(Integer, nullable=False)  
    domain = Column(String(255), nullable=False)  
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    user = relationship('User', back_populates='monitored_certificates')

def filter_and_save_certificate(certificate_id, domain):
    session = Session()

    try:
        
        keywords = session.query(Keyword).all()

        
        for keyword in keywords:
            if keyword.keyword.lower() in domain.lower():
                
                monitored_certificate = MonitoredCertificate(
                    user_id=keyword.user_id,
                    certificate_id=certificate_id,
                    domain=domain,
                    timestamp=datetime.utcnow()
                )
                session.add(monitored_certificate)
                session.commit()
                logger.info(f"Certificado monitorado salvo para o usuário {keyword.user_id}: {domain}")
                break

    except SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Erro ao salvar certificado monitorado: {e}")
    finally:
        session.close()

def run():
    
    with grpc.insecure_channel('stream.olivsec.com.br:50051') as channel:
        stub = realtime_pb2_grpc.CertStreamServiceStub(channel)

        
        request = realtime_pb2.StreamRequest(request_key="YpGVQBFckw9wG3vCiZ9CJe0YV03pufWU")

        try:
            responses = stub.StreamCertificates(request)

            for response in responses:
                
                cert_data = json.loads(response.certificate_data)
                certificate_id = cert_data.get('id')
                domain = cert_data.get('domain')

                logger.info(f"Certificado recebido: ID={certificate_id}, Domain={domain}")

                
                filter_and_save_certificate(certificate_id, domain)

        except grpc.RpcError as e:
            logger.error(f"Erro na conexão gRPC: {e.details()}")

if __name__ == '__main__':
    run()
