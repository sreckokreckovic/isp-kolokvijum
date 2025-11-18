package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, provide integrity to the channel
 * using HMAC implemted with SHA256. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AgentCommunicationHMAC {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for hash based message authentication code.
         */
        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String text = "I hope you get this message intact. Kisses, Alice.";
                final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                final Mac aliceMac = Mac.getInstance("HmacSha256");
                aliceMac.init(key);
                final byte[] tag = aliceMac.doFinal(pt);
                final int tagLen  =  aliceMac.getMacLength();

                byte[] msg = new byte[tagLen+pt.length];

                System.arraycopy(tag,0,msg,0,tagLen);
                System.arraycopy(pt,0,msg,tagLen,pt.length);
                send("bob", msg);
                Thread.sleep(200);

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                byte[] received = receive("alice");
                final Mac bobMac = Mac.getInstance("HmacSHA256");
                bobMac.init(key);
                final int tagLen = bobMac.getMacLength();
                if (received.length < tagLen) {
                    System.out.println("[Bob] Invalid message format: too short.");
                }
                byte[] tag = new byte[tagLen];
                byte[] message = new byte[received.length-tagLen];
                System.arraycopy(received,0,tag,0,tag.length);
                System.arraycopy(received, tagLen, message, 0, message.length);
                final byte[] tagCheck = bobMac.doFinal(message);
                if (MessageDigest.isEqual(tag, tagCheck)) {
                    System.out.println("[Bob] CORRECT ");
                } else {
                    System.out.println("[Bob]  Integrity FAIL! Message was modified.");
                }

                System.out.println("------------------------------------------------------------");
                Thread.sleep(200);
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
