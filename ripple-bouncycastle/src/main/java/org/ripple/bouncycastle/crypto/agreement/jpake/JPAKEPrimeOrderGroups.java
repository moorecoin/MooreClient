package org.ripple.bouncycastle.crypto.agreement.jpake;

import java.math.biginteger;

/**
 * standard pre-computed prime order groups for use by j-pake.
 * (j-pake can use pre-computed prime order groups, same as dsa and diffie-hellman.)
 * <p/>
 * <p/>
 * this class contains some convenient constants for use as input for
 * constructing {@link jpakeparticipant}s.
 * <p/>
 * <p/>
 * the prime order groups below are taken from sun's jdk javadoc (docs/guide/security/cryptospec.html#appb),
 * and from the prime order groups
 * <a href="http://csrc.nist.gov/groups/st/toolkit/documents/examples/dsa2_all.pdf">published by nist</a>.
 */
public class jpakeprimeordergroups
{
    /**
     * from sun's jdk javadoc (docs/guide/security/cryptospec.html#appb)
     * 1024-bit p, 160-bit q and 1024-bit g for 80-bit security.
     */
    public static final jpakeprimeordergroup sun_jce_1024 = new jpakeprimeordergroup(
        // p
        new biginteger(
            "fd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669" +
                "455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b7" +
                "6b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb" +
                "83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c7", 16),
        // q
        new biginteger(
            "9760508f15230bccb292b982a2eb840bf0581cf5", 16),
        // g
        new biginteger(
            "f7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d078267" +
                "5159578ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e1" +
                "3c167a8b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243b" +
                "cca4f1bea8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a", 16),
        true
    );

    /**
     * from nist.
     * 2048-bit p, 224-bit q and 2048-bit g for 112-bit security.
     */
    public static final jpakeprimeordergroup nist_2048 = new jpakeprimeordergroup(
        // p
        new biginteger(
            "c196ba05ac29e1f9c3c72d56dffc6154a033f1477ac88ec37f09be6c5bb95f51" +
                "c296dd20d1a28a067ccc4d4316a4bd1dca55ed1066d438c35aebaabf57e7dae4" +
                "28782a95eca1c143db701fd48533a3c18f0fe23557ea7ae619ecacc7e0b51652" +
                "a8776d02a425567ded36eabd90ca33a1e8d988f0bbb92d02d1d20290113bb562" +
                "ce1fc856eeb7cdd92d33eea6f410859b179e7e789a8f75f645fae2e136d252bf" +
                "faff89528945c1abe705a38dbc2d364aade99be0d0aad82e5320121496dc65b3" +
                "930e38047294ff877831a16d5228418de8ab275d7d75651cefed65f78afc3ea7" +
                "fe4d79b35f62a0402a1117599adac7b269a59f353cf450e6982d3b1702d9ca83", 16),
        // q
        new biginteger(
            "90eaf4d1af0708b1b612ff35e0a2997eb9e9d263c9ce659528945c0d", 16),
        // g
        new biginteger(
            "a59a749a11242c58c894e9e5a91804e8fa0ac64b56288f8d47d51b1edc4d6544" +
                "4feca0111d78f35fc9fdd4cb1f1b79a3ba9cbee83a3f811012503c8117f98e50" +
                "48b089e387af6949bf8784ebd9ef45876f2e6a5a495be64b6e770409494b7fee" +
                "1dbb1e4b2bc2a53d4f893d418b7159592e4fffdf6969e91d770daebd0b5cb14c" +
                "00ad68ec7dc1e5745ea55c706c4a1c5c88964e34d09deb753ad418c1ad0f4fdf" +
                "d049a955e5d78491c0b7a2f1575a008ccd727ab376db6e695515b05bd412f5b8" +
                "c2f4c77ee10da48abd53f5dd498927ee7b692bbbcda2fb23a516c5b4533d7398" +
                "0b2a3b60e384ed200ae21b40d273651ad6060c13d97fd69aa13c5611a51b9085", 16),
        true
    );

    /**
     * from nist.
     * 3072-bit p, 256-bit q and 3072-bit g for 128-bit security.
     */
    public static final jpakeprimeordergroup nist_3072 = new jpakeprimeordergroup(
        // p
        new biginteger(
            "90066455b5cfc38f9caa4a48b4281f292c260feef01fd61037e56258a7795a1c" +
                "7ad46076982ce6bb956936c6ab4dcfe05e6784586940ca544b9b2140e1eb523f" +
                "009d20a7e7880e4e5bfa690f1b9004a27811cd9904af70420eefd6ea11ef7da1" +
                "29f58835ff56b89faa637bc9ac2efaab903402229f491d8d3485261cd068699b" +
                "6ba58a1ddbbef6db51e8fe34e8a78e542d7ba351c21ea8d8f1d29f5d5d159394" +
                "87e27f4416b0ca632c59efd1b1eb66511a5a0fbf615b766c5862d0bd8a3fe7a0" +
                "e0da0fb2fe1fcb19e8f9996a8ea0fccde538175238fc8b0ee6f29af7f642773e" +
                "be8cd5402415a01451a840476b2fceb0e388d30d4b376c37fe401c2a2c2f941d" +
                "ad179c540c1c8ce030d460c4d983be9ab0b20f69144c1ae13f9383ea1c08504f" +
                "b0bf321503efe43488310dd8dc77ec5b8349b8bfe97c2c560ea878de87c11e3d" +
                "597f1fea742d73eec7f37be43949ef1a0d15c3f3e3fc0a8335617055ac91328e" +
                "c22b50fc15b941d3d1624cd88bc25f3e941fddc6200689581bfec416b4b2cb73", 16),
        // q
        new biginteger(
            "cfa0478a54717b08ce64805b76e5b14249a77a4838469df7f7dc987efccfb11d", 16),
        // g
        new biginteger(
            "5e5cba992e0a680d885eb903aea78e4a45a469103d448ede3b7accc54d521e37" +
                "f84a4bdd5b06b0970cc2d2bbb715f7b82846f9a0c393914c792e6a923e2117ab" +
                "805276a975aadb5261d91673ea9aaffeecbfa6183dfcb5d3b7332aa19275afa1" +
                "f8ec0b60fb6f66cc23ae4870791d5982aad1aa9485fd8f4a60126feb2cf05db8" +
                "a7f0f09b3397f3937f2e90b9e5b9c9b6efef642bc48351c46fb171b9bfa9ef17" +
                "a961ce96c7e7a7cc3d3d03dfad1078ba21da425198f07d2481622bce45969d9c" +
                "4d6063d72ab7a0f08b2f49a7cc6af335e08c4720e31476b67299e231f8bd90b3" +
                "9ac3ae3be0c6b6cacef8289a2e2873d58e51e029cafbd55e6841489ab66b5b4b" +
                "9ba6e2f784660896aff387d92844ccb8b69475496de19da2e58259b090489ac8" +
                "e62363cdf82cfd8ef2a427abcd65750b506f56dde3b988567a88126b914d7828" +
                "e2b63a6d7ed0747ec59e0e0a23ce7d8a74c1d2c2a7afb6a29799620f00e11c33" +
                "787f7ded3b30e1a22d09f1fbda1abbbfbf25cae05a13f812e34563f99410e73b", 16),
        true
    );

}
