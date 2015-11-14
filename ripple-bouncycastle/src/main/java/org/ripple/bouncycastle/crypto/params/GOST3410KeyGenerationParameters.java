package org.ripple.bouncycastle.crypto.params;

import org.ripple.bouncycastle.crypto.keygenerationparameters;

import java.security.securerandom;

public class gost3410keygenerationparameters
        extends keygenerationparameters
{
        private gost3410parameters    params;

        public gost3410keygenerationparameters(
            securerandom    random,
            gost3410parameters   params)
        {
            super(random, params.getp().bitlength() - 1);

            this.params = params;
        }

        public gost3410parameters getparameters()
        {
            return params;
        }
}
