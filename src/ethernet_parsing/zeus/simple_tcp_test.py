#!/usr/bin/env python3
"""
Simple TCP server test to see if we can receive connections on 10.0.0.2:8080
"""
import socket
import threading
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def handle_client(conn, addr):
    """Handle client connection"""
    logger.info(f"🎉 SUCCESS! TCP connection established from {addr}")
    try:
        data = conn.recv(1024)
        logger.info(f"📥 Received data: {data[:100]}...")
        
        # Send simple HTTP response
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!"
        conn.send(response)
        logger.info(f"📤 Sent HTTP response to {addr}")
    except Exception as e:
        logger.error(f"Error handling client {addr}: {e}")
    finally:
        conn.close()
        logger.info(f"🔚 Connection closed to {addr}")

def main():
    """Simple TCP server test"""
    try:
        # Try binding to different addresses
        test_addresses = [
            ('10.0.0.2', 8080),
            ('0.0.0.0', 8080),
            ('127.0.0.1', 8080)
        ]
        
        for addr, port in test_addresses:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((addr, port))
                sock.listen(5)
                
                logger.info(f"✅ Successfully bound to {addr}:{port}")
                logger.info(f"🔊 Listening for connections on {addr}:{port}...")
                
                while True:
                    conn, client_addr = sock.accept()
                    logger.info(f"🔗 New connection attempt from {client_addr}")
                    
                    # Handle in separate thread
                    thread = threading.Thread(target=handle_client, args=(conn, client_addr))
                    thread.start()
                    
            except Exception as e:
                logger.error(f"❌ Failed to bind to {addr}:{port}: {e}")
                continue
                
    except KeyboardInterrupt:
        logger.info("Server interrupted")
    except Exception as e:
        logger.error(f"Server error: {e}")

if __name__ == "__main__":
    main()
