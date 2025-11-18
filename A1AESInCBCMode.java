package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using
 * AES in CBC mode. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AESInCBCMode {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        // STEP 2: Setup communication
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "I love you Bob. Kisses, Alice.";
                System.out.println("[Alice]: " +message);

                final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
                System.out.println("[Alice][PT]: "+ hex(pt));

                final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE,key);
                final byte[] encrypted = cipher.doFinal(pt);
                System.out.println("[Alice][CT]: " + hex(encrypted));

                final byte[] iv = cipher.getIV();
                send("bob",iv);
                send("bob",encrypted);

                final byte[] receivedIv = receive("bob");
                final byte[] receivedMessage = receive("bob");

                cipher.init(Cipher.DECRYPT_MODE,key,new IvParameterSpec(receivedIv));
                final byte[] decrypted = cipher.doFinal(receivedMessage);
                System.out.println("[Alice][DEC]: " + new String(decrypted));
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final byte[] iv = receive("alice");
                final byte[] encrypted = receive("alice");

                final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE,key,new IvParameterSpec(iv));
                final byte[] plainText = cipher.doFinal(encrypted);
                System.out.println("[Bob][DEC]: " + new String(plainText));

                final String msg = "Hi, ALice.It's bob here!";
                final byte[] bobPt = msg.getBytes(StandardCharsets.UTF_8);
                System.out.println("[Bob][PT]: " + hex(bobPt));


                cipher.init(Cipher.ENCRYPT_MODE,key);
                final byte[] ct = cipher.doFinal(bobPt);
                System.out.println("[Bob][CT]: " + hex(ct));

                send("alice",cipher.getIV());
                send("alice",ct);

            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
