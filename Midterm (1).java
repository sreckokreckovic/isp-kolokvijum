package isp.keyagreement;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class Midterm {

    public static byte[] hash(byte[] hash) throws NoSuchAlgorithmException {
        final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
        return digestAlgorithm.digest(hash);
    }


    public static void main(String[] args) throws NoSuchAlgorithmException {

        final Environment env = new Environment();

        final KeyPair kpServer = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        String pwd = "alicePWD123";

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(256);
                final KeyPair keyPair = kpg.generateKeyPair();
                PublicKey A = keyPair.getPublic();
                PrivateKey a = keyPair.getPrivate();
                send("server", A.getEncoded());


                final byte[] ct = receive("server");
                final byte[] iv = receive("server");
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("server"));
                final ECPublicKey B = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);
                final byte[] o = receive("server");

                final Signature verifier = Signature.getInstance("SHA256withRSA");
                verifier.initVerify(kpServer.getPublic());
                verifier.update((hex(A.getEncoded()) + hex(B.getEncoded())).getBytes(StandardCharsets.UTF_8));

                if (verifier.verify(o)) {
                    print("Valid signature.");

                    final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                    dh.init(a);
                    dh.doPhase(B, true);
                    final byte[] sharedSecret = dh.generateSecret();
                    final byte[] k = Arrays.copyOfRange(hash(sharedSecret), 0, 16);

                    final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                    aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k, "AES"), new GCMParameterSpec(128, iv));
                    final byte[] chall = aes.doFinal(ct);

                    final byte[] resp = hash((pwd + new String(chall, StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8));
                    aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "AES"));
                    final byte[] ct2 = aes.doFinal(resp);
                    final byte[] iv2 = aes.getIV();

                    send("server", ct2);
                    send("server", iv2);
                }
                else {
                    print("Invalid signature.");
                }

            }
        });

        env.add(new Agent("server") {
            @Override
            public void task() throws Exception {
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(256);
                final KeyPair keyPair = kpg.generateKeyPair();
                PublicKey B = keyPair.getPublic();
                PrivateKey b = keyPair.getPrivate();

                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("alice"));
                final ECPublicKey A = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);
                final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                dh.init(b);
                dh.doPhase(A, true);
                final byte[] sharedSecret = dh.generateSecret();

                final byte[] k = Arrays.copyOfRange(hash(sharedSecret), 0, 16);

                final Signature signer = Signature.getInstance("SHA256withRSA");
                signer.initSign(kpServer.getPrivate());
                signer.update((hex(A.getEncoded()) + hex(B.getEncoded())).getBytes(StandardCharsets.UTF_8));
                final byte[] o = signer.sign();

                byte[] chall = new byte[32];
                SecureRandom.getInstanceStrong().nextBytes(chall);

                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "AES"));
                final byte[] ct = aes.doFinal(chall);
                final byte[] iv = aes.getIV();

                send("alice", ct);
                send("alice", iv);
                send("alice", B.getEncoded());
                send("alice", o);

                final byte[] ct2 = receive("alice");
                final byte[] iv2 = receive("alice");
                aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k, "AES"), new GCMParameterSpec(128, iv2));
                final byte[] resp = aes.doFinal(ct2);
                final byte[] resp2 = hash((pwd + new String(chall, StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8));

                if (MessageDigest.isEqual(resp, resp2)) {
                    print("OK");
                } else {
                    print("FAIL");
                }
            }
        });

        env.connect("alice", "server");
        env.start();
    }
}
