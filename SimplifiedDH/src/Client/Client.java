package Client;

import Cipher.DiffieHellman;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * Created by carlosmorais on 01/03/16.
 */
public class Client {

    private static void log(String s){
        System.out.println(s);
    }

    public static void main(String[] args) throws IOException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException {
        String host = "localhost";
        int port = 4444;
        Socket socket = new Socket(host, port);
        DiffieHellman dh = new DiffieHellman();
        BufferedReader in =
                new BufferedReader(new InputStreamReader(System.in));
        PrintWriter out = new PrintWriter(socket.getOutputStream());
        dh.proceedDHagreement(new BufferedReader(new InputStreamReader(socket.getInputStream())), out);
        String line;

        while((line = in.readLine()) != null){
            line =  Base64.getEncoder().encodeToString(dh.encrypt(line.getBytes()));
            out.println(line);
            out.flush();
        }

        socket.shutdownInput();
        socket.shutdownOutput();
        socket.close();

    }
}
