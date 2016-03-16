package Server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Created by carlosmorais on 01/03/16.
 */
public class Server {
    public static void main(String[] args) throws IOException {
        int port = 4444;
        int clientCount = 0;
        ServerSocket server = new ServerSocket(port);

        while(true){
            Socket socket = server.accept();
            new Thread(new ClientHandler(socket, ++clientCount)).start();
        }

    }
}
