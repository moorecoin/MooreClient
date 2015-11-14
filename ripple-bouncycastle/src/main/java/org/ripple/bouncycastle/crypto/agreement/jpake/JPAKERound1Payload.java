package org.ripple.bouncycastle.crypto.agreement.jpake;

import java.math.biginteger;

import org.ripple.bouncycastle.util.arrays;

/**
 * the payload sent/received during the first round of a j-pake exchange.
 * <p/>
 * <p/>
 * each {@link jpakeparticipant} creates and sends an instance
 * of this payload to the other {@link jpakeparticipant}.
 * the payload to send should be created via
 * {@link jpakeparticipant#createround1payloadtosend()}.
 * <p/>
 * <p/>
 * each {@link jpakeparticipant} must also validate the payload
 * received from the other {@link jpakeparticipant}.
 * the received payload should be validated via
 * {@link jpakeparticipant#validateround1payloadreceived(jpakeround1payload)}.
 * <p/>
 */
public class jpakeround1payload
{
    /**
     * the id of the {@link jpakeparticipant} who created/sent this payload.
     */
    private final string participantid;

    /**
     * the value of g^x1
     */
    private final biginteger gx1;

    /**
     * the value of g^x2
     */
    private final biginteger gx2;

    /**
     * the zero knowledge proof for x1.
     * <p/>
     * this is a two element array, containing {g^v, r} for x1.
     */
    private final biginteger[] knowledgeproofforx1;

    /**
     * the zero knowledge proof for x2.
     * <p/>
     * this is a two element array, containing {g^v, r} for x2.
     */
    private final biginteger[] knowledgeproofforx2;

    public jpakeround1payload(
        string participantid,
        biginteger gx1,
        biginteger gx2,
        biginteger[] knowledgeproofforx1,
        biginteger[] knowledgeproofforx2)
    {
        jpakeutil.validatenotnull(participantid, "participantid");
        jpakeutil.validatenotnull(gx1, "gx1");
        jpakeutil.validatenotnull(gx2, "gx2");
        jpakeutil.validatenotnull(knowledgeproofforx1, "knowledgeproofforx1");
        jpakeutil.validatenotnull(knowledgeproofforx2, "knowledgeproofforx2");

        this.participantid = participantid;
        this.gx1 = gx1;
        this.gx2 = gx2;
        this.knowledgeproofforx1 = arrays.copyof(knowledgeproofforx1, knowledgeproofforx1.length);
        this.knowledgeproofforx2 = arrays.copyof(knowledgeproofforx2, knowledgeproofforx2.length);
    }

    public string getparticipantid()
    {
        return participantid;
    }

    public biginteger getgx1()
    {
        return gx1;
    }

    public biginteger getgx2()
    {
        return gx2;
    }

    public biginteger[] getknowledgeproofforx1()
    {
        return arrays.copyof(knowledgeproofforx1, knowledgeproofforx1.length);
    }

    public biginteger[] getknowledgeproofforx2()
    {
        return arrays.copyof(knowledgeproofforx2, knowledgeproofforx2.length);
    }

}
