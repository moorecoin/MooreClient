package org.ripple.bouncycastle.crypto.agreement.jpake;

import java.math.biginteger;
import java.security.securerandom;

import org.ripple.bouncycastle.crypto.cryptoexception;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.digests.sha256digest;
import org.ripple.bouncycastle.util.arrays;

/**
 * a participant in a password authenticated key exchange by juggling (j-pake) exchange.
 * <p/>
 * <p/>
 * the j-pake exchange is defined by feng hao and peter ryan in the paper
 * <a href="http://grouper.ieee.org/groups/1363/research/contributions/hao-ryan-2008.pdf">
 * "password authenticated key exchange by juggling, 2008."</a>
 * <p/>
 * <p/>
 * the j-pake protocol is symmetric.
 * there is no notion of a <i>client</i> or <i>server</i>, but rather just two <i>participants</i>.
 * an instance of {@link jpakeparticipant} represents one participant, and
 * is the primary interface for executing the exchange.
 * <p/>
 * <p/>
 * to execute an exchange, construct a {@link jpakeparticipant} on each end,
 * and call the following 7 methods
 * (once and only once, in the given order, for each participant, sending messages between them as described):
 * <ol>
 * <li>{@link #createround1payloadtosend()} - and send the payload to the other participant</li>
 * <li>{@link #validateround1payloadreceived(jpakeround1payload)} - use the payload received from the other participant</li>
 * <li>{@link #createround2payloadtosend()} - and send the payload to the other participant</li>
 * <li>{@link #validateround2payloadreceived(jpakeround2payload)} - use the payload received from the other participant</li>
 * <li>{@link #calculatekeyingmaterial()}</li>
 * <li>{@link #createround3payloadtosend(biginteger)} - and send the payload to the other participant</li>
 * <li>{@link #validateround3payloadreceived(jpakeround3payload, biginteger)} - use the payload received from the other participant</li>
 * </ol>
 * <p/>
 * <p/>
 * each side should derive a session key from the keying material returned by {@link #calculatekeyingmaterial()}.
 * the caller is responsible for deriving the session key using a secure key derivation function (kdf).
 * <p/>
 * <p/>
 * round 3 is an optional key confirmation process.
 * if you do not execute round 3, then there is no assurance that both participants are using the same key.
 * (i.e. if the participants used different passwords, then their session keys will differ.)
 * <p/>
 * <p/>
 * if the round 3 validation succeeds, then the keys are guaranteed to be the same on both sides.
 * <p/>
 * <p/>
 * the symmetric design can easily support the asymmetric cases when one party initiates the communication.
 * e.g. sometimes the round1 payload and round2 payload may be sent in one pass.
 * also, in some cases, the key confirmation payload can be sent together with the round2 payload.
 * these are the trivial techniques to optimize the communication.
 * <p/>
 * <p/>
 * the key confirmation process is implemented as specified in
 * <a href="http://csrc.nist.gov/publications/nistpubs/800-56a/sp800-56a_revision1_mar08-2007.pdf">nist sp 800-56a revision 1</a>,
 * section 8.2 unilateral key confirmation for key agreement schemes.
 * <p/>
 * <p/>
 * this class is stateful and not threadsafe.
 * each instance should only be used for one complete j-pake exchange
 * (i.e. a new {@link jpakeparticipant} should be constructed for each new j-pake exchange).
 * <p/>
 * <p/>
 * see {@link jpakeexample} for example usage.
 */
public class jpakeparticipant
{
    /*
     * possible internal states.  used for state checking.
     */

    public static final int state_initialized = 0;
    public static final int state_round_1_created = 10;
    public static final int state_round_1_validated = 20;
    public static final int state_round_2_created = 30;
    public static final int state_round_2_validated = 40;
    public static final int state_key_calculated = 50;
    public static final int state_round_3_created = 60;
    public static final int state_round_3_validated = 70;

    /**
     * unique identifier of this participant.
     * the two participants in the exchange must not share the same id.
     */
    private final string participantid;

    /**
     * shared secret.  this only contains the secret between construction
     * and the call to {@link #calculatekeyingmaterial()}.
     * <p/>
     * i.e. when {@link #calculatekeyingmaterial()} is called, this buffer overwritten with 0's,
     * and the field is set to null.
     */
    private char[] password;

    /**
     * digest to use during calculations.
     */
    private final digest digest;

    /**
     * source of secure random data.
     */
    private final securerandom random;

    private final biginteger p;
    private final biginteger q;
    private final biginteger g;

    /**
     * the participantid of the other participant in this exchange.
     */
    private string partnerparticipantid;

    /**
     * alice's x1 or bob's x3.
     */
    private biginteger x1;
    /**
     * alice's x2 or bob's x4.
     */
    private biginteger x2;
    /**
     * alice's g^x1 or bob's g^x3.
     */
    private biginteger gx1;
    /**
     * alice's g^x2 or bob's g^x4.
     */
    private biginteger gx2;
    /**
     * alice's g^x3 or bob's g^x1.
     */
    private biginteger gx3;
    /**
     * alice's g^x4 or bob's g^x2.
     */
    private biginteger gx4;
    /**
     * alice's b or bob's a.
     */
    private biginteger b;

    /**
     * the current state.
     * see the <tt>state_*</tt> constants for possible values.
     */
    private int state;

    /**
     * convenience constructor for a new {@link jpakeparticipant} that uses
     * the {@link jpakeprimeordergroups#nist_3072} prime order group,
     * a sha-256 digest, and a default {@link securerandom} implementation.
     * <p/>
     * after construction, the {@link #getstate() state} will be  {@link #state_initialized}.
     *
     * @param participantid unique identifier of this participant.
     *                      the two participants in the exchange must not share the same id.
     * @param password      shared secret.
     *                      a defensive copy of this array is made (and cleared once {@link #calculatekeyingmaterial()} is called).
     *                      caller should clear the input password as soon as possible.
     * @throws nullpointerexception if any argument is null
     * @throws illegalargumentexception if password is empty
     */
    public jpakeparticipant(
        string participantid,
        char[] password)
    {
        this(
            participantid,
            password,
            jpakeprimeordergroups.nist_3072);
    }


    /**
     * convenience constructor for a new {@link jpakeparticipant} that uses
     * a sha-256 digest and a default {@link securerandom} implementation.
     * <p/>
     * after construction, the {@link #getstate() state} will be  {@link #state_initialized}.
     *
     * @param participantid unique identifier of this participant.
     *                      the two participants in the exchange must not share the same id.
     * @param password      shared secret.
     *                      a defensive copy of this array is made (and cleared once {@link #calculatekeyingmaterial()} is called).
     *                      caller should clear the input password as soon as possible.
     * @param group         prime order group.
     *                      see {@link jpakeprimeordergroups} for standard groups
     * @throws nullpointerexception if any argument is null
     * @throws illegalargumentexception if password is empty
     */
    public jpakeparticipant(
        string participantid,
        char[] password,
        jpakeprimeordergroup group)
    {
        this(
            participantid,
            password,
            group,
            new sha256digest(),
            new securerandom());
    }


    /**
     * construct a new {@link jpakeparticipant}.
     * <p/>
     * after construction, the {@link #getstate() state} will be  {@link #state_initialized}.
     *
     * @param participantid unique identifier of this participant.
     *                      the two participants in the exchange must not share the same id.
     * @param password      shared secret.
     *                      a defensive copy of this array is made (and cleared once {@link #calculatekeyingmaterial()} is called).
     *                      caller should clear the input password as soon as possible.
     * @param group         prime order group.
     *                      see {@link jpakeprimeordergroups} for standard groups
     * @param digest        digest to use during zero knowledge proofs and key confirmation (sha-256 or stronger preferred)
     * @param random        source of secure random data for x1 and x2, and for the zero knowledge proofs
     * @throws nullpointerexception if any argument is null
     * @throws illegalargumentexception if password is empty
     */
    public jpakeparticipant(
        string participantid,
        char[] password,
        jpakeprimeordergroup group,
        digest digest,
        securerandom random)
    {
        jpakeutil.validatenotnull(participantid, "participantid");
        jpakeutil.validatenotnull(password, "password");
        jpakeutil.validatenotnull(group, "p");
        jpakeutil.validatenotnull(digest, "digest");
        jpakeutil.validatenotnull(random, "random");
        if (password.length == 0)
        {
            throw new illegalargumentexception("password must not be empty.");
        }

        this.participantid = participantid;
        
        /*
         * create a defensive copy so as to fully encapsulate the password.
         * 
         * this array will contain the password for the lifetime of this
         * participant before {@link #calculatekeyingmaterial()} is called.
         * 
         * i.e. when {@link #calculatekeyingmaterial()} is called, the array will be cleared
         * in order to remove the password from memory.
         * 
         * the caller is responsible for clearing the original password array
         * given as input to this constructor.
         */
        this.password = arrays.copyof(password, password.length);

        this.p = group.getp();
        this.q = group.getq();
        this.g = group.getg();

        this.digest = digest;
        this.random = random;

        this.state = state_initialized;
    }

    /**
     * gets the current state of this participant.
     * see the <tt>state_*</tt> constants for possible values.
     */
    public int getstate()
    {
        return this.state;
    }

    /**
     * creates and returns the payload to send to the other participant during round 1.
     * <p/>
     * <p/>
     * after execution, the {@link #getstate() state} will be  {@link #state_round_1_created}.
     */
    public jpakeround1payload createround1payloadtosend()
    {
        if (this.state >= state_round_1_created)
        {
            throw new illegalstateexception("round1 payload already created for " + participantid);
        }

        this.x1 = jpakeutil.generatex1(q, random);
        this.x2 = jpakeutil.generatex2(q, random);

        this.gx1 = jpakeutil.calculategx(p, g, x1);
        this.gx2 = jpakeutil.calculategx(p, g, x2);
        biginteger[] knowledgeproofforx1 = jpakeutil.calculatezeroknowledgeproof(p, q, g, gx1, x1, participantid, digest, random);
        biginteger[] knowledgeproofforx2 = jpakeutil.calculatezeroknowledgeproof(p, q, g, gx2, x2, participantid, digest, random);

        this.state = state_round_1_created;

        return new jpakeround1payload(participantid, gx1, gx2, knowledgeproofforx1, knowledgeproofforx2);
    }

    /**
     * validates the payload received from the other participant during round 1.
     * <p/>
     * <p/>
     * must be called prior to {@link #createround2payloadtosend()}.
     * <p/>
     * <p/>
     * after execution, the {@link #getstate() state} will be  {@link #state_round_1_validated}.
     *
     * @throws cryptoexception if validation fails.
     * @throws illegalstateexception if called multiple times.
     */
    public void validateround1payloadreceived(jpakeround1payload round1payloadreceived)
        throws cryptoexception
    {
        if (this.state >= state_round_1_validated)
        {
            throw new illegalstateexception("validation already attempted for round1 payload for" + participantid);
        }
        this.partnerparticipantid = round1payloadreceived.getparticipantid();
        this.gx3 = round1payloadreceived.getgx1();
        this.gx4 = round1payloadreceived.getgx2();

        biginteger[] knowledgeproofforx3 = round1payloadreceived.getknowledgeproofforx1();
        biginteger[] knowledgeproofforx4 = round1payloadreceived.getknowledgeproofforx2();

        jpakeutil.validateparticipantidsdiffer(participantid, round1payloadreceived.getparticipantid());
        jpakeutil.validategx4(gx4);
        jpakeutil.validatezeroknowledgeproof(p, q, g, gx3, knowledgeproofforx3, round1payloadreceived.getparticipantid(), digest);
        jpakeutil.validatezeroknowledgeproof(p, q, g, gx4, knowledgeproofforx4, round1payloadreceived.getparticipantid(), digest);

        this.state = state_round_1_validated;
    }

    /**
     * creates and returns the payload to send to the other participant during round 2.
     * <p/>
     * <p/>
     * {@link #validateround1payloadreceived(jpakeround1payload)} must be called prior to this method.
     * <p/>
     * <p/>
     * after execution, the {@link #getstate() state} will be  {@link #state_round_2_created}.
     *
     * @throws illegalstateexception if called prior to {@link #validateround1payloadreceived(jpakeround1payload)}, or multiple times
     */
    public jpakeround2payload createround2payloadtosend()
    {
        if (this.state >= state_round_2_created)
        {
            throw new illegalstateexception("round2 payload already created for " + this.participantid);
        }
        if (this.state < state_round_1_validated)
        {
            throw new illegalstateexception("round1 payload must be validated prior to creating round2 payload for " + this.participantid);
        }
        biginteger ga = jpakeutil.calculatega(p, gx1, gx3, gx4);
        biginteger s = jpakeutil.calculates(password);
        biginteger x2s = jpakeutil.calculatex2s(q, x2, s);
        biginteger a = jpakeutil.calculatea(p, q, ga, x2s);
        biginteger[] knowledgeproofforx2s = jpakeutil.calculatezeroknowledgeproof(p, q, ga, a, x2s, participantid, digest, random);

        this.state = state_round_2_created;

        return new jpakeround2payload(participantid, a, knowledgeproofforx2s);
    }

    /**
     * validates the payload received from the other participant during round 2.
     * <p/>
     * <p/>
     * note that this does not detect a non-common password.
     * the only indication of a non-common password is through derivation
     * of different keys (which can be detected explicitly by executing round 3 and round 4)
     * <p/>
     * <p/>
     * must be called prior to {@link #calculatekeyingmaterial()}.
     * <p/>
     * <p/>
     * after execution, the {@link #getstate() state} will be  {@link #state_round_2_validated}.
     *
     * @throws cryptoexception if validation fails.
     * @throws illegalstateexception if called prior to {@link #validateround1payloadreceived(jpakeround1payload)}, or multiple times
     */
    public void validateround2payloadreceived(jpakeround2payload round2payloadreceived)
        throws cryptoexception
    {
        if (this.state >= state_round_2_validated)
        {
            throw new illegalstateexception("validation already attempted for round2 payload for" + participantid);
        }
        if (this.state < state_round_1_validated)
        {
            throw new illegalstateexception("round1 payload must be validated prior to validating round2 payload for " + this.participantid);
        }
        biginteger gb = jpakeutil.calculatega(p, gx3, gx1, gx2);
        this.b = round2payloadreceived.geta();
        biginteger[] knowledgeproofforx4s = round2payloadreceived.getknowledgeproofforx2s();

        jpakeutil.validateparticipantidsdiffer(participantid, round2payloadreceived.getparticipantid());
        jpakeutil.validateparticipantidsequal(this.partnerparticipantid, round2payloadreceived.getparticipantid());
        jpakeutil.validatega(gb);
        jpakeutil.validatezeroknowledgeproof(p, q, gb, b, knowledgeproofforx4s, round2payloadreceived.getparticipantid(), digest);

        this.state = state_round_2_validated;
    }

    /**
     * calculates and returns the key material.
     * a session key must be derived from this key material using a secure key derivation function (kdf).
     * the kdf used to derive the key is handled externally (i.e. not by {@link jpakeparticipant}).
     * <p/>
     * <p/>
     * the keying material will be identical for each participant if and only if
     * each participant's password is the same.  i.e. if the participants do not
     * share the same password, then each participant will derive a different key.
     * therefore, if you immediately start using a key derived from
     * the keying material, then you must handle detection of incorrect keys.
     * if you want to handle this detection explicitly, you can optionally perform
     * rounds 3 and 4.  see {@link jpakeparticipant} for details on how to execute
     * rounds 3 and 4.
     * <p/>
     * <p/>
     * the keying material will be in the range <tt>[0, p-1]</tt>.
     * <p/>
     * <p/>
     * {@link #validateround2payloadreceived(jpakeround2payload)} must be called prior to this method.
     * <p/>
     * <p/>
     * as a side effect, the internal {@link #password} array is cleared, since it is no longer needed.
     * <p/>
     * <p/>
     * after execution, the {@link #getstate() state} will be  {@link #state_key_calculated}.
     *
     * @throws illegalstateexception if called prior to {@link #validateround2payloadreceived(jpakeround2payload)},
     * or if called multiple times.
     */
    public biginteger calculatekeyingmaterial()
    {
        if (this.state >= state_key_calculated)
        {
            throw new illegalstateexception("key already calculated for " + participantid);
        }
        if (this.state < state_round_2_validated)
        {
            throw new illegalstateexception("round2 payload must be validated prior to creating key for " + participantid);
        }
        biginteger s = jpakeutil.calculates(password);
        
        /*
         * clear the password array from memory, since we don't need it anymore.
         * 
         * also set the field to null as a flag to indicate that the key has already been calculated.
         */
        arrays.fill(password, (char)0);
        this.password = null;

        biginteger keyingmaterial = jpakeutil.calculatekeyingmaterial(p, q, gx4, x2, s, b);
        
        /*
         * clear the ephemeral private key fields as well.
         * note that we're relying on the garbage collector to do its job to clean these up.
         * the old objects will hang around in memory until the garbage collector destroys them.
         * 
         * if the ephemeral private keys x1 and x2 are leaked,
         * the attacker might be able to brute-force the password.
         */
        this.x1 = null;
        this.x2 = null;
        this.b = null;
        
        /*
         * do not clear gx* yet, since those are needed by round 3.
         */

        this.state = state_key_calculated;

        return keyingmaterial;
    }


    /**
     * creates and returns the payload to send to the other participant during round 3.
     * <p/>
     * <p/>
     * see {@link jpakeparticipant} for more details on round 3.
     * <p/>
     * <p/>
     * after execution, the {@link #getstate() state} will be  {@link #state_round_3_created}.
     *
     * @param keyingmaterial the keying material as returned from {@link #calculatekeyingmaterial()}.
     * @throws illegalstateexception if called prior to {@link #calculatekeyingmaterial()}, or multiple times
     */
    public jpakeround3payload createround3payloadtosend(biginteger keyingmaterial)
    {
        if (this.state >= state_round_3_created)
        {
            throw new illegalstateexception("round3 payload already created for " + this.participantid);
        }
        if (this.state < state_key_calculated)
        {
            throw new illegalstateexception("keying material must be calculated prior to creating round3 payload for " + this.participantid);
        }

        biginteger mactag = jpakeutil.calculatemactag(
            this.participantid,
            this.partnerparticipantid,
            this.gx1,
            this.gx2,
            this.gx3,
            this.gx4,
            keyingmaterial,
            this.digest);

        this.state = state_round_3_created;

        return new jpakeround3payload(participantid, mactag);
    }

    /**
     * validates the payload received from the other participant during round 3.
     * <p/>
     * <p/>
     * see {@link jpakeparticipant} for more details on round 3.
     * <p/>
     * <p/>
     * after execution, the {@link #getstate() state} will be {@link #state_round_3_validated}.
     *
     * @param keyingmaterial the keying material as returned from {@link #calculatekeyingmaterial()}.
     * @throws cryptoexception if validation fails.
     * @throws illegalstateexception if called prior to {@link #calculatekeyingmaterial()}, or multiple times
     */
    public void validateround3payloadreceived(jpakeround3payload round3payloadreceived, biginteger keyingmaterial)
        throws cryptoexception
    {
        if (this.state >= state_round_3_validated)
        {
            throw new illegalstateexception("validation already attempted for round3 payload for" + participantid);
        }
        if (this.state < state_key_calculated)
        {
            throw new illegalstateexception("keying material must be calculated validated prior to validating round3 payload for " + this.participantid);
        }
        jpakeutil.validateparticipantidsdiffer(participantid, round3payloadreceived.getparticipantid());
        jpakeutil.validateparticipantidsequal(this.partnerparticipantid, round3payloadreceived.getparticipantid());

        jpakeutil.validatemactag(
            this.participantid,
            this.partnerparticipantid,
            this.gx1,
            this.gx2,
            this.gx3,
            this.gx4,
            keyingmaterial,
            this.digest,
            round3payloadreceived.getmactag());
        
        
        /*
         * clear the rest of the fields.
         */
        this.gx1 = null;
        this.gx2 = null;
        this.gx3 = null;
        this.gx4 = null;

        this.state = state_round_3_validated;
    }

}
