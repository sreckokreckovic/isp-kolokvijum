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
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using a
 * AES in counter mode. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A2AESInCTRMode {
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
                final byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

                final Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE,key);
                final byte[] ct = cipher.doFinal(messageBytes);

                System.out.println("[Alice]: " + message);
                System.out.println("[Alice][CT]: " + hex(ct));

                send("bob",cipher.getIV());
                send("bob",ct);

                final byte[] receivedIv = receive("bob");
                final byte[] receivedCt = receive("bob");

                cipher.init(Cipher.DECRYPT_MODE,key,new IvParameterSpec(receivedIv));
                final byte[] dec = cipher.doFinal(receivedCt);
                System.out.println("[Alice][DEC]: " + new String(dec,StandardCharsets.UTF_8));
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final byte[] receivedIv = receive("alice");
                final byte[] receivedMessage = receive("alice");

                final Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE,key,new IvParameterSpec(receivedIv));
                final byte[] decrypted = cipher.doFinal(receivedMessage);
                System.out.println("[Bob][DEC]: " + new String(decrypted));

                final String pt = "Hi Alice,It's me, Bob!";
                final byte[] ptBytes = pt.getBytes(StandardCharsets.UTF_8);

                final Cipher cipher1 = Cipher.getInstance("AES/CTR/NoPadding");
                cipher1.init(Cipher.ENCRYPT_MODE,key);
                final byte[] encrypted = cipher1.doFinal(ptBytes);
                System.out.println("[Bob][ENC]: " + hex(encrypted));

                send("alice",cipher1.getIV());
                send("alice",encrypted);
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
