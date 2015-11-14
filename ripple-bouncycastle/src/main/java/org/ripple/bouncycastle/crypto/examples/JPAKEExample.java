package org.ripple.bouncycastle.crypto.examples;

import java.math.biginteger;
import java.security.securerandom;

import org.ripple.bouncycastle.crypto.cryptoexception;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.agreement.jpake.jpakeparticipant;
import org.ripple.bouncycastle.crypto.agreement.jpake.jpakeprimeordergroup;
import org.ripple.bouncycastle.crypto.agreement.jpake.jpakeprimeordergroups;
import org.ripple.bouncycastle.crypto.agreement.jpake.jpakeround1payload;
import org.ripple.bouncycastle.crypto.agreement.jpake.jpakeround2payload;
import org.ripple.bouncycastle.crypto.agreement.jpake.jpakeround3payload;
import org.ripple.bouncycastle.crypto.digests.sha256digest;

/**
 * an example of a j-pake exchange.
 * <p>
 * 
 * in this example, both alice and bob are on the same computer (in the same jvm, in fact).
 * in reality, alice and bob would be in different locations,
 * and would be sending their generated payloads to each other.
 */
public class jpakeexample
{

    public static void main(string args[]) throws cryptoexception
    {
        /*
         * initialization
         * 
         * pick an appropriate prime order group to use throughout the exchange.
         * note that both participants must use the same group.
         */
        jpakeprimeordergroup group = jpakeprimeordergroups.nist_3072;

        biginteger p = group.getp();
        biginteger q = group.getq();
        biginteger g = group.getg();

        string alicepassword = "password";
        string bobpassword = "password";

        system.out.println("********* initialization **********");
        system.out.println("public parameters for the cyclic group:");
        system.out.println("p (" + p.bitlength() + " bits): " + p.tostring(16));
        system.out.println("q (" + q.bitlength() + " bits): " + q.tostring(16));
        system.out.println("g (" + p.bitlength() + " bits): " + g.tostring(16));
        system.out.println("p mod q = " + p.mod(q).tostring(16));
        system.out.println("g^{q} mod p = " + g.modpow(q, p).tostring(16));
        system.out.println("");

        system.out.println("(secret passwords used by alice and bob: " +
                "\"" + alicepassword + "\" and \"" + bobpassword + "\")\n");

        /*
         * both participants must use the same hashing algorithm.
         */
        digest digest = new sha256digest();
        securerandom random = new securerandom();

        jpakeparticipant alice = new jpakeparticipant("alice", alicepassword.tochararray(), group, digest, random);
        jpakeparticipant bob = new jpakeparticipant("bob", bobpassword.tochararray(), group, digest, random);

        /*
         * round 1
         * 
         * alice and bob each generate a round 1 payload, and send it to each other.
         */

        jpakeround1payload aliceround1payload = alice.createround1payloadtosend();
        jpakeround1payload bobround1payload = bob.createround1payloadtosend();

        system.out.println("************ round 1 **************");
        system.out.println("alice sends to bob: ");
        system.out.println("g^{x1}=" + aliceround1payload.getgx1().tostring(16));
        system.out.println("g^{x2}=" + aliceround1payload.getgx2().tostring(16));
        system.out.println("kp{x1}={" + aliceround1payload.getknowledgeproofforx1()[0].tostring(16) + "};{" + aliceround1payload.getknowledgeproofforx1()[1].tostring(16) + "}");
        system.out.println("kp{x2}={" + aliceround1payload.getknowledgeproofforx2()[0].tostring(16) + "};{" + aliceround1payload.getknowledgeproofforx2()[1].tostring(16) + "}");
        system.out.println("");

        system.out.println("bob sends to alice: ");
        system.out.println("g^{x3}=" + bobround1payload.getgx1().tostring(16));
        system.out.println("g^{x4}=" + bobround1payload.getgx2().tostring(16));
        system.out.println("kp{x3}={" + bobround1payload.getknowledgeproofforx1()[0].tostring(16) + "};{" + bobround1payload.getknowledgeproofforx1()[1].tostring(16) + "}");
        system.out.println("kp{x4}={" + bobround1payload.getknowledgeproofforx2()[0].tostring(16) + "};{" + bobround1payload.getknowledgeproofforx2()[1].tostring(16) + "}");
        system.out.println("");

        /*
         * each participant must then validate the received payload for round 1
         */

        alice.validateround1payloadreceived(bobround1payload);
        system.out.println("alice checks g^{x4}!=1: ok");
        system.out.println("alice checks kp{x3}: ok");
        system.out.println("alice checks kp{x4}: ok");
        system.out.println("");

        bob.validateround1payloadreceived(aliceround1payload);
        system.out.println("bob checks g^{x2}!=1: ok");
        system.out.println("bob checks kp{x1},: ok");
        system.out.println("bob checks kp{x2},: ok");
        system.out.println("");

        /*
         * round 2
         * 
         * alice and bob each generate a round 2 payload, and send it to each other.
         */

        jpakeround2payload aliceround2payload = alice.createround2payloadtosend();
        jpakeround2payload bobround2payload = bob.createround2payloadtosend();

        system.out.println("************ round 2 **************");
        system.out.println("alice sends to bob: ");
        system.out.println("a=" + aliceround2payload.geta().tostring(16));
        system.out.println("kp{x2*s}={" + aliceround2payload.getknowledgeproofforx2s()[0].tostring(16) + "},{" + aliceround2payload.getknowledgeproofforx2s()[1].tostring(16) + "}");
        system.out.println("");

        system.out.println("bob sends to alice");
        system.out.println("b=" + bobround2payload.geta().tostring(16));
        system.out.println("kp{x4*s}={" + bobround2payload.getknowledgeproofforx2s()[0].tostring(16) + "},{" + bobround2payload.getknowledgeproofforx2s()[1].tostring(16) + "}");
        system.out.println("");

        /*
         * each participant must then validate the received payload for round 2
         */

        alice.validateround2payloadreceived(bobround2payload);
        system.out.println("alice checks kp{x4*s}: ok\n");

        bob.validateround2payloadreceived(aliceround2payload);
        system.out.println("bob checks kp{x2*s}: ok\n");

        /*
         * after round 2, each participant computes the keying material.
         */

        biginteger alicekeyingmaterial = alice.calculatekeyingmaterial();
        biginteger bobkeyingmaterial = bob.calculatekeyingmaterial();

        system.out.println("********* after round 2 ***********");
        system.out.println("alice computes key material \t k=" + alicekeyingmaterial.tostring(16));
        system.out.println("bob computes key material \t k=" + bobkeyingmaterial.tostring(16));
        system.out.println();
        
        
        /*
         * you must derive a session key from the keying material applicable
         * to whatever encryption algorithm you want to use.
         */
        
        biginteger alicekey = derivesessionkey(alicekeyingmaterial);
        biginteger bobkey = derivesessionkey(bobkeyingmaterial);
        
        /*
         * at this point, you can stop and use the session keys if you want.
         * this is implicit key confirmation.
         * 
         * if you want to explicitly confirm that the key material matches,
         * you can continue on and perform round 3.
         */
        
        /*
         * round 3
         * 
         * alice and bob each generate a round 3 payload, and send it to each other.
         */

        jpakeround3payload aliceround3payload = alice.createround3payloadtosend(alicekeyingmaterial);
        jpakeround3payload bobround3payload = bob.createround3payloadtosend(bobkeyingmaterial);

        system.out.println("************ round 3 **************");
        system.out.println("alice sends to bob: ");
        system.out.println("mactag=" + aliceround3payload.getmactag().tostring(16));
        system.out.println("");
        system.out.println("bob sends to alice: ");
        system.out.println("mactag=" + bobround3payload.getmactag().tostring(16));
        system.out.println("");

        /*
         * each participant must then validate the received payload for round 3
         */

        alice.validateround3payloadreceived(bobround3payload, alicekeyingmaterial);
        system.out.println("alice checks mactag: ok\n");

        bob.validateround3payloadreceived(aliceround3payload, bobkeyingmaterial);
        system.out.println("bob checks mactag: ok\n");

        system.out.println();
        system.out.println("mactags validated, therefore the keying material matches.");
    }

    private static biginteger derivesessionkey(biginteger keyingmaterial)
    {
        /*
         * you should use a secure key derivation function (kdf) to derive the session key.
         * 
         * for the purposes of this example, i'm just going to use a hash of the keying material.
         */
        sha256digest digest = new sha256digest();
        
        byte[] keybytearray = keyingmaterial.tobytearray();
        
        byte[] output = new byte[digest.getdigestsize()];
        
        digest.update(keybytearray, 0, keybytearray.length);

        digest.dofinal(output, 0);

        return new biginteger(output);
    }
}
