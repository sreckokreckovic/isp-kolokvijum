package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, secure the channel using a
 * AES in GCM. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AgentCommunicationGCM {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for AES in GCM.
         */
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String text = "I hope you get this message intact and in secret. Kisses, Alice.";
                final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                final Cipher encryption = Cipher.getInstance("AES/GCM/NoPAdding");
                encryption.init(Cipher.ENCRYPT_MODE,key);
                final byte[] ct = encryption.doFinal(pt);
                System.out.println("[Alice][MSG]: "+ text);
                System.out.println("[Alice][PT]: "+ hex(pt));
                System.out.println("[Alice][CT]: "+ hex(ct));

                send("bob",encryption.getIV());
                send("bob",ct);

                final byte[] receivedIV = receive("bob");
                final byte[] receivedCT = receive("bob");

                final Cipher decryption = Cipher.getInstance("AES/GCM/NoPAdding");
                decryption.init(Cipher.DECRYPT_MODE,key,new GCMParameterSpec(128,receivedIV));
                final byte[] dec = decryption.doFinal(receivedCT);

                System.out.println("[Alice][DEC]: "+ new String(dec,StandardCharsets.UTF_8));

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final byte[] receivedIv = receive("alice");
                final byte[] receivedCt = receive("alice");

                final Cipher decryption = Cipher.getInstance("AES/GCM/NoPadding");
                decryption.init(Cipher.DECRYPT_MODE,key,new GCMParameterSpec(128,receivedIv));
                final byte[] dec = decryption.doFinal(receivedCt);
                System.out.println("[BOB][CT]: "+ hex(receivedCt));
                System.out.println("[BOB][DEC]: " + new String(dec));

                final String bobMsg = "Hi, Alice. It's Bob";
                final byte[] pt = bobMsg.getBytes(StandardCharsets.UTF_8);

                final Cipher enc = Cipher.getInstance("AES/GCM/NoPadding");
                enc.init(Cipher.ENCRYPT_MODE,key);
                final byte[] ct = enc.doFinal(pt);
                System.out.println("-----------------------------------------------------------------");
                System.out.println("[BOB][MSG]: "+ bobMsg);
                System.out.println("[BOB][PT]: "+ hex(pt));
                System.out.println("[BOB][CT]: "+ hex(ct));

                send("alice",enc.getIV());
                send("alice",ct);

            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
