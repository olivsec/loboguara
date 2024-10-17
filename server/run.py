import os
from app import create_app, start_scheduler, socketio
import subprocess

app = create_app()

if __name__ == "__main__":
    
    host = os.getenv('LOBOGUARA_HOST', '0.0.0.0')  
    port = int(os.getenv('LOBOGUARA_PORT', 7405))   

    
    start_scheduler(app)
    grpc_client_path = os.path.join(os.path.dirname(__file__), 'gRPC_Client.py')
    try:
        subprocess.Popen(['python3', grpc_client_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        app.logger.info("gRPC Client iniciado como processo separado.")
    except Exception as e:
        app.logger.error(f"Erro ao iniciar o gRPC Client: {str(e)}")

    
    socketio.run(app, host=host, port=port, debug=False)