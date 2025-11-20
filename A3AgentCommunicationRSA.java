package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class A3AgentCommunicationRSA {
    public static void main(String[] args) throws Exception {

        final KeyPair aliceKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final KeyPair bobKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String text = "Hi,Bob.It's Alice";
                final byte[] textBytes = text.getBytes();
                System.out.println("[ALICE][MSG]: "+ text);


                final Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
                cipher.init(Cipher.ENCRYPT_MODE,bobKP.getPublic());
                final byte[] encrypted = cipher.doFinal(textBytes);
                System.out.println("[ALICE][CT]: " + hex(encrypted));

                send("bob",encrypted);

                byte[] received = receive("bob");
                cipher.init(Cipher.DECRYPT_MODE,aliceKP.getPrivate());
                final byte[] decrypted = cipher.doFinal(received);
                System.out.println("[ALICE][DEC]: " + new String(decrypted));

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final byte[] receivedCt = receive("alice");
                System.out.println("[BOB][RECEIVED]: "+ hex(receivedCt));

                final Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
                cipher.init(Cipher.DECRYPT_MODE,bobKP.getPrivate());
                final byte[] decrypted = cipher.doFinal(receivedCt);

                System.out.println("[BOB][DECRYPTED]: "+ new String(decrypted));


                final String message = "Hi, Alice. It's bob here.POZZZZZZZZZZZ";
                byte[] bytes  = message.getBytes();

                cipher.init(Cipher.ENCRYPT_MODE,aliceKP.getPublic());
                byte[] encAlice = cipher.doFinal(bytes);
                System.out.println("[BOB][MSG]: "+ message);
                System.out.println("[BOB][ENCRYPTED]: "+ hex(encAlice));

                send("alice",encAlice);
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
