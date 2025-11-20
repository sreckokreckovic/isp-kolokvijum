package isp.signatures;

import fri.isp.Agent;
import fri.isp.Environment;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

/*
 * Assuming Alice and Bob know each other's public key, provide integrity and non-repudiation
 * to exchanged messages with ECDSA. Then exchange ten signed messages between Alice and Bob.
 */
public class A2AgentCommunicationSignature {
    public static void main(String[] args) {
        final Environment env = new Environment();

        final KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("EC");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        final KeyPair aliceKP = kpg.generateKeyPair();
        final KeyPair bobKP = kpg.generateKeyPair();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "Hi Bob, It's Alice";
                Signature signer = Signature.getInstance("SHA256withECDSA");
                signer.initSign(aliceKP.getPrivate());
                signer.update(message.getBytes());
                final byte[] signature = signer.sign();
                send("bob",message.getBytes());
                send("bob",signature);


                final byte[] receivedMessage = receive("bob");
                final byte[] signatureReceived = receive("bob");

                final Signature verify = Signature.getInstance("SHA256withECDSA");
                verify.initVerify(bobKP.getPublic());
                verify.update(receivedMessage);

                if(verify.verify(signatureReceived)) {
                    System.out.println("Signature verified");
                } else {
                    System.out.println("Signature verification failed");
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final byte[] message = receive("alice");
                final byte[] signature = receive("alice");

                final Signature verify = Signature.getInstance("SHA256withECDSA");
                verify.initVerify(aliceKP.getPublic());
                verify.update(message);

                if(verify.verify(signature)) {
                    System.out.println("Signature verified");
                } else{
                    System.out.println("Signature verification failed");
                }

                final String text = "Hi Alice, It's bob";
                final Signature signer = Signature.getInstance("SHA256withECDSA");
                signer.initSign(bobKP.getPrivate());
                signer.update(text.getBytes());

                final byte[] signatureBob = signer.sign();

                send("alice",text.getBytes());
                send("alice",signatureBob);

            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}