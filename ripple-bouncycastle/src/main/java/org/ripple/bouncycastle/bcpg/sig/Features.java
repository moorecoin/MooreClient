package org.ripple.bouncycastle.bcpg.sig;

import org.ripple.bouncycastle.bcpg.signaturesubpacket;
import org.ripple.bouncycastle.bcpg.signaturesubpackettags;

public class features
    extends signaturesubpacket
{

    /** identifier for the modification detection feature */
    public static final byte feature_modification_detection = 1;

    private static final byte[] featuretobytearray(byte feature)
    {
        byte[] data = new byte[1];
        data[0] = feature;
        return data;
    }

    public features(boolean critical, byte[] data)
    {
        super(signaturesubpackettags.features, critical, data);
    }

    public features(boolean critical, byte feature)
    {
        super(signaturesubpackettags.features, critical, featuretobytearray(feature));
    }

    /**
     * returns if modification detection is supported.
     */
    public boolean supportsmodificationdetection()
    {
        return supportsfeature(feature_modification_detection);
    }


//    /**  class should be immutable.
//     * set modification detection support.
//     */
//    public void setsupportsmodificationdetection(boolean support)
//    {
//        setsupportsfeature(feature_modification_detection, support);
//    }


    /**
     * returns if a particular feature is supported.
     */
    public boolean supportsfeature(byte feature)
    {
        for (int i = 0; i < data.length; i++)
        {
            if (data[i] == feature)
            {
                return true;
            }
        }
        return false;
    }


    /**
     * sets support for a particular feature.
     */
    private void setsupportsfeature(byte feature, boolean support)
    {
        if (feature == 0)
        {
            throw new illegalargumentexception("feature == 0");
        }
        if (supportsfeature(feature) != support)
        {
            if (support == true)
            {
                byte[] temp = new byte[data.length + 1];
                system.arraycopy(data, 0, temp, 0, data.length);
                temp[data.length] = feature;
                data = temp;
            }
            else
            {
                for (int i = 0; i < data.length; i++)
                {
                    if (data[i] == feature)
                    {
                        byte[] temp = new byte[data.length - 1];
                        system.arraycopy(data, 0, temp, 0, i);
                        system.arraycopy(data, i + 1, temp, i, temp.length - i);
                        data = temp;
                        break;
                    }
                }
            }
        }
    }
}
