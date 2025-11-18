package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.ChaCha20ParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using
 * ChaCha20 stream cipher. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A3ChaCha20 {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("ChaCha20").generateKey();

        // STEP 2: Setup communication
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "I love you Bob. Kisses, Alice.";
                final byte[] messageBytes = message.getBytes();

                final byte[] nonce = new byte[12];
                new SecureRandom().nextBytes(nonce);
                final int counter = 0;

                final Cipher cipher = Cipher.getInstance("ChaCha20");
                cipher.init(Cipher.ENCRYPT_MODE,key,new ChaCha20ParameterSpec(nonce,counter));
                final byte[]ct = cipher.doFinal(messageBytes);

                send("bob",nonce);
                send("bob",ct);

                System.out.println("[Alice]: "+ message);
                System.out.println("[Alice][CT]: "+ hex(ct));

                final byte[] bobNonce = receive("bob");
                final byte[] ctBob = receive("bob");

                final Cipher decryption = Cipher.getInstance("ChaCha20");
                decryption.init(Cipher.DECRYPT_MODE,key,new ChaCha20ParameterSpec(bobNonce,0));
                final byte[] decrypted = decryption.doFinal(ctBob);
                System.out.println("[Alice][Receive]: "+ hex(ctBob));
                System.out.println("[Alice][DEC]: "+ new String(decrypted));

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final byte[] nonce = receive("alice");
                final byte[] messageReceived = receive("alice");

                final Cipher cipher = Cipher.getInstance("ChaCha20");
                cipher.init(Cipher.DECRYPT_MODE,key,new ChaCha20ParameterSpec(nonce,0));
                final byte[] pt = cipher.doFinal(messageReceived);
                System.out.println("[Bob][Received]: "+ hex(messageReceived));
                System.out.println("[Bob][DEC]: " + new String(pt));

                final byte[] nonceBob = new byte[12];
                new SecureRandom().nextBytes(nonceBob);
                String msg = "Hi Alice, It's bob";
                final byte[] msgBytes = msg.getBytes(StandardCharsets.UTF_8);

                final Cipher enc = Cipher.getInstance("ChaCha20");
                enc.init(Cipher.ENCRYPT_MODE,key,new ChaCha20ParameterSpec(nonceBob,0));
                final byte[] ct = enc.doFinal(msgBytes);
                System.out.println("[Bob]: "+ msg);
                System.out.println("[Bob][Encrypted]: "+ hex(ct));
                send("alice",nonceBob);
                send("alice",ct);
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
