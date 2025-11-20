package isp.keyagreement;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

/*
 * Implement an unauthenticated (as presented in the slides) key exchange between Alice and Bob
 * using public-key encryption. Once the shared secret is established, send an encrypted message
 * from Alice to Bob using AES in GCM.
 */
public class A1AgentCommunicationKeyExchange {
    public static void main(String[] args) {
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                final KeyPair aliceKp = kpg.generateKeyPair();
                send("bob",aliceKp.getPublic().getEncoded());

                final byte[] encAesKey = receive("bob");

                final Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.DECRYPT_MODE,aliceKp.getPrivate());
                final byte[] aesKey = cipher.doFinal(encAesKey);

                final SecretKeySpec secretKeySpec = new SecretKeySpec(aesKey, "AES");

                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.ENCRYPT_MODE,secretKeySpec);
                final String text = "Hi bob, its alice";
                final byte[] ct = aes.doFinal(text.getBytes());

                send("bob",aes.getIV());
                send("bob",ct);







            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final byte[] alicePkBytes = receive("alice");

                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(alicePkBytes);
                final KeyFactory kf = KeyFactory.getInstance("RSA");
                final PublicKey alicePK = kf.generatePublic(keySpec);

                final Key aesKey = KeyGenerator.getInstance("AES").generateKey();

                final Cipher rsa = Cipher.getInstance("RSA");
                rsa.init(Cipher.ENCRYPT_MODE,alicePK);
                final byte[] encrypted = rsa.doFinal(aesKey.getEncoded());

                send("alice",encrypted);

                final byte[] receivedIv = receive("alice");
                final byte[] ct = receive("alice");

                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.DECRYPT_MODE,aesKey,new GCMParameterSpec(128,receivedIv));
                final byte[] decrypted = aes.doFinal(ct);

                System.out.println("Dekritpovano: "+ new String(decrypted));



            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
