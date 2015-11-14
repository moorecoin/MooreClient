package org.ripple.bouncycastle.crypto.agreement;

import java.math.biginteger;

import org.ripple.bouncycastle.crypto.params.dhparameters;
import org.ripple.bouncycastle.util.encoders.hex;

/**
 * standard diffie-hellman groups from various ietf specifications.
 */
public class dhstandardgroups
{

    private static dhparameters frompg(string hexp, string hexg)
    {
        biginteger p = new biginteger(1, hex.decode(hexp));
        biginteger g = new biginteger(1, hex.decode(hexg));
        return new dhparameters(p, g);
    }

    private static dhparameters frompgq(string hexp, string hexg, string hexq)
    {
        biginteger p = new biginteger(1, hex.decode(hexp));
        biginteger g = new biginteger(1, hex.decode(hexg));
        biginteger q = new biginteger(1, hex.decode(hexq));
        return new dhparameters(p, g, q);
    }

    /*
     * rfc 2409
     */
    private static final string rfc2409_768_p = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1"
        + "29024e088a67cc74020bbea63b139b22514a08798e3404dd" + "ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245"
        + "e485b576625e7ec6f44c42e9a63a3620ffffffffffffffff";
    private static final string rfc2409_768_g = "02";
    public static final dhparameters rfc2409_768 = frompg(rfc2409_768_p, rfc2409_768_g);

    private static final string rfc2409_1024_p = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1"
        + "29024e088a67cc74020bbea63b139b22514a08798e3404dd" + "ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245"
        + "e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed" + "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381"
        + "ffffffffffffffff";
    private static final string rfc2409_1024_g = "02";
    public static final dhparameters rfc2409_1024 = frompg(rfc2409_1024_p, rfc2409_1024_g);

    /*
     * rfc 3526
     */
    private static final string rfc3526_1536_p = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1"
        + "29024e088a67cc74020bbea63b139b22514a08798e3404dd" + "ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245"
        + "e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed" + "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3d"
        + "c2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f" + "83655d23dca3ad961c62f356208552bb9ed529077096966d"
        + "670c354e4abc9804f1746c08ca237327ffffffffffffffff";
    private static final string rfc3526_1536_g = "02";
    public static final dhparameters rfc3526_1536 = frompg(rfc3526_1536_p, rfc3526_1536_g);

    private static final string rfc3526_2048_p = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1"
        + "29024e088a67cc74020bbea63b139b22514a08798e3404dd" + "ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245"
        + "e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed" + "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3d"
        + "c2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f" + "83655d23dca3ad961c62f356208552bb9ed529077096966d"
        + "670c354e4abc9804f1746c08ca18217c32905e462e36ce3b" + "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9"
        + "de2bcbf6955817183995497cea956ae515d2261898fa0510" + "15728e5a8aacaa68ffffffffffffffff";
    private static final string rfc3526_2048_g = "02";
    public static final dhparameters rfc3526_2048 = frompg(rfc3526_2048_p, rfc3526_2048_g);

    private static final string rfc3526_3072_p = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1"
        + "29024e088a67cc74020bbea63b139b22514a08798e3404dd" + "ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245"
        + "e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed" + "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3d"
        + "c2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f" + "83655d23dca3ad961c62f356208552bb9ed529077096966d"
        + "670c354e4abc9804f1746c08ca18217c32905e462e36ce3b" + "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9"
        + "de2bcbf6955817183995497cea956ae515d2261898fa0510" + "15728e5a8aaac42dad33170d04507a33a85521abdf1cba64"
        + "ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7" + "abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6b"
        + "f12ffa06d98a0864d87602733ec86a64521f2b18177b200c" + "bbe117577a615d6c770988c0bad946e208e24fa074e5ab31"
        + "43db5bfce0fd108e4b82d120a93ad2caffffffffffffffff";
    private static final string rfc3526_3072_g = "02";
    public static final dhparameters rfc3526_3072 = frompg(rfc3526_3072_p, rfc3526_3072_g);

    private static final string rfc3526_4096_p = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1"
        + "29024e088a67cc74020bbea63b139b22514a08798e3404dd" + "ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245"
        + "e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed" + "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3d"
        + "c2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f" + "83655d23dca3ad961c62f356208552bb9ed529077096966d"
        + "670c354e4abc9804f1746c08ca18217c32905e462e36ce3b" + "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9"
        + "de2bcbf6955817183995497cea956ae515d2261898fa0510" + "15728e5a8aaac42dad33170d04507a33a85521abdf1cba64"
        + "ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7" + "abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6b"
        + "f12ffa06d98a0864d87602733ec86a64521f2b18177b200c" + "bbe117577a615d6c770988c0bad946e208e24fa074e5ab31"
        + "43db5bfce0fd108e4b82d120a92108011a723c12a787e6d7" + "88719a10bdba5b2699c327186af4e23c1a946834b6150bda"
        + "2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6" + "287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed"
        + "1f612970cee2d7afb81bdd762170481cd0069127d5b05aa9" + "93b4ea988d8fddc186ffb7dc90a6c08f4df435c934063199"
        + "ffffffffffffffff";
    private static final string rfc3526_4096_g = "02";
    public static final dhparameters rfc3526_4096 = frompg(rfc3526_4096_p, rfc3526_4096_g);

    private static final string rfc3526_6144_p = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e08"
        + "8a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b"
        + "302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9"
        + "a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe6"
        + "49286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8"
        + "fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d"
        + "670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c"
        + "180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718"
        + "3995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d"
        + "04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7d"
        + "b3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d226"
        + "1ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200c"
        + "bbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfc"
        + "e0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b26"
        + "99c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db"
        + "04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2"
        + "233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127"
        + "d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c934028492"
        + "36c3fab4d27c7026c1d4dcb2602646dec9751e763dba37bdf8ff9406"
        + "ad9e530ee5db382f413001aeb06a53ed9027d831179727b0865a8918"
        + "da3edbebcf9b14ed44ce6cbaced4bb1bdb7f1447e6cc254b33205151"
        + "2bd7af426fb8f401378cd2bf5983ca01c64b92ecf032ea15d1721d03"
        + "f482d7ce6e74fef6d55e702f46980c82b5a84031900b1c9e59e7c97f"
        + "bec7e8f323a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154aa"
        + "cc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be32806a1d58b"
        + "b7c5da76f550aa3d8a1fbff0eb19ccb1a313d55cda56c9ec2ef29632"
        + "387fe8d76e3c0468043e8f663f4860ee12bf2d5b0b7474d6e694f91e" + "6dcc4024ffffffffffffffff";
    private static final string rfc3526_6144_g = "02";
    public static final dhparameters rfc3526_6144 = frompg(rfc3526_6144_p, rfc3526_6144_g);

    private static final string rfc3526_8192_p = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1"
        + "29024e088a67cc74020bbea63b139b22514a08798e3404dd" + "ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245"
        + "e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed" + "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3d"
        + "c2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f" + "83655d23dca3ad961c62f356208552bb9ed529077096966d"
        + "670c354e4abc9804f1746c08ca18217c32905e462e36ce3b" + "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9"
        + "de2bcbf6955817183995497cea956ae515d2261898fa0510" + "15728e5a8aaac42dad33170d04507a33a85521abdf1cba64"
        + "ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7" + "abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6b"
        + "f12ffa06d98a0864d87602733ec86a64521f2b18177b200c" + "bbe117577a615d6c770988c0bad946e208e24fa074e5ab31"
        + "43db5bfce0fd108e4b82d120a92108011a723c12a787e6d7" + "88719a10bdba5b2699c327186af4e23c1a946834b6150bda"
        + "2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6" + "287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed"
        + "1f612970cee2d7afb81bdd762170481cd0069127d5b05aa9" + "93b4ea988d8fddc186ffb7dc90a6c08f4df435c934028492"
        + "36c3fab4d27c7026c1d4dcb2602646dec9751e763dba37bd" + "f8ff9406ad9e530ee5db382f413001aeb06a53ed9027d831"
        + "179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1b" + "db7f1447e6cc254b332051512bd7af426fb8f401378cd2bf"
        + "5983ca01c64b92ecf032ea15d1721d03f482d7ce6e74fef6" + "d55e702f46980c82b5a84031900b1c9e59e7c97fbec7e8f3"
        + "23a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154aa" + "cc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be328"
        + "06a1d58bb7c5da76f550aa3d8a1fbff0eb19ccb1a313d55c" + "da56c9ec2ef29632387fe8d76e3c0468043e8f663f4860ee"
        + "12bf2d5b0b7474d6e694f91e6dbe115974a3926f12fee5e4" + "38777cb6a932df8cd8bec4d073b931ba3bc832b68d9dd300"
        + "741fa7bf8afc47ed2576f6936ba424663aab639c5ae4f568" + "3423b4742bf1c978238f16cbe39d652de3fdb8befc848ad9"
        + "22222e04a4037c0713eb57a81a23f0c73473fc646cea306b" + "4bcbc8862f8385ddfa9d4b7fa2c087e879683303ed5bdd3a"
        + "062b3cf5b3a278a66d2a13f83f44f82ddf310ee074ab6a36" + "4597e899a0255dc164f31cc50846851df9ab48195ded7ea1"
        + "b1d510bd7ee74d73faf36bc31ecfa268359046f4eb879f92" + "4009438b481c6cd7889a002ed5ee382bc9190da6fc026e47"
        + "9558e4475677e9aa9e3050e2765694dfc81f56e880b96e71" + "60c980dd98edd3dfffffffffffffffff";
    private static final string rfc3526_8192_g = "02";
    public static final dhparameters rfc3526_8192 = frompg(rfc3526_8192_p, rfc3526_8192_g);

    /*
     * rfc 4306
     */
    public static final dhparameters rfc4306_768 = rfc2409_768;
    public static final dhparameters rfc4306_1024 = rfc2409_1024;

    /*
     * rfc 5114
     */
    private static final string rfc5114_1024_160_p = "b10b8f96a080e01dde92de5eae5d54ec52c99fbcfb06a3c6"
        + "9a6a9dca52d23b616073e28675a23d189838ef1e2ee652c0" + "13ecb4aea906112324975c3cd49b83bfaccbdd7d90c4bd70"
        + "98488e9c219a73724effd6fae5644738faa31a4ff55bccc0" + "a151af5f0dc8b4bd45bf37df365c1a65e68cfda76d4da708"
        + "df1fb2bc2e4a4371";
    private static final string rfc5114_1024_160_g = "a4d1cbd5c3fd34126765a442efb99905f8104dd258ac507f"
        + "d6406cff14266d31266fea1e5c41564b777e690f5504f213" + "160217b4b01b886a5e91547f9e2749f4d7fbd7d3b9a92ee1"
        + "909d0d2263f80a76a6a24c087a091f531dbf0a0169b6a28a" + "d662a4d18e73afa32d779d5918d08bc8858f4dcef97c2a24"
        + "855e6eeb22b3b2e5";
    private static final string rfc5114_1024_160_q = "f518aa8781a8df278aba4e7d64b7cb9d49462353";
    public static final dhparameters rfc5114_1024_160 = frompgq(rfc5114_1024_160_p, rfc5114_1024_160_g,
        rfc5114_1024_160_q);

    private static final string rfc5114_2048_224_p = "ad107e1e9123a9d0d660faa79559c51fa20d64e5683b9fd1"
        + "b54b1597b61d0a75e6fa141df95a56dbaf9a3c407ba1df15" + "eb3d688a309c180e1de6b85a1274a0a66d3f8152ad6ac212"
        + "9037c9edefda4df8d91e8fef55b7394b7ad5b7d0b6c12207" + "c9f98d11ed34dbf6c6ba0b2c8bbc27be6a00e0a0b9c49708"
        + "b3bf8a317091883681286130bc8985db1602e714415d9330" + "278273c7de31efdc7310f7121fd5a07415987d9adc0a486d"
        + "cdf93acc44328387315d75e198c641a480cd86a1b9e587e8" + "be60e69cc928b2b9c52172e413042e9b23f10b0e16e79763"
        + "c9b53dcf4ba80a29e3fb73c16b8e75b97ef363e2ffa31f71" + "cf9de5384e71b81c0ac4dffe0c10e64f";
    private static final string rfc5114_2048_224_g = "ac4032ef4f2d9ae39df30b5c8ffdac506cdebe7b89998caf"
        + "74866a08cfe4ffe3a6824a4e10b9a6f0dd921f01a70c4afa" + "ab739d7700c29f52c57db17c620a8652be5e9001a8d66ad7"
        + "c17669101999024af4d027275ac1348bb8a762d0521bc98a" + "e247150422ea1ed409939d54da7460cdb5f6c6b250717cbe"
        + "f180eb34118e98d119529a45d6f834566e3025e316a330ef" + "bb77a86f0c1ab15b051ae3d428c8f8acb70a8137150b8eeb"
        + "10e183edd19963ddd9e263e4770589ef6aa21e7f5f2ff381" + "b539cce3409d13cd566afbb48d6c019181e1bcfe94b30269"
        + "edfe72fe9b6aa4bd7b5a0f1c71cfff4c19c418e1f6ec0179" + "81bc087f2a7065b384b890d3191f2bfa";
    private static final string rfc5114_2048_224_q = "801c0d34c58d93fe997177101f80535a4738cebcbf389a99b36371eb";
    public static final dhparameters rfc5114_2048_224 = frompgq(rfc5114_2048_224_p, rfc5114_2048_224_g,
        rfc5114_2048_224_q);

    private static final string rfc5114_2048_256_p = "87a8e61db4b6663cffbbd19c651959998ceef608660dd0f2"
        + "5d2ceed4435e3b00e00df8f1d61957d4faf7df4561b2aa30" + "16c3d91134096faa3bf4296d830e9a7c209e0c6497517abd"
        + "5a8a9d306bcf67ed91f9e6725b4758c022e0b1ef4275bf7b" + "6c5bfc11d45f9088b941f54eb1e59bb8bc39a0bf12307f5c"
        + "4fdb70c581b23f76b63acae1caa6b7902d52526735488a0e" + "f13c6d9a51bfa4ab3ad8347796524d8ef6a167b5a41825d9"
        + "67e144e5140564251ccacb83e6b486f6b3ca3f7971506026" + "c0b857f689962856ded4010abd0be621c3a3960a54e710c3"
        + "75f26375d7014103a4b54330c198af126116d2276e11715f" + "693877fad7ef09cadb094ae91e1a1597";
    private static final string rfc5114_2048_256_g = "3fb32c9b73134d0b2e77506660edbd484ca7b18f21ef2054"
        + "07f4793a1a0ba12510dbc15077be463fff4fed4aac0bb555" + "be3a6c1b0c6b47b1bc3773bf7e8c6f62901228f8c28cbb18"
        + "a55ae31341000a650196f931c77a57f2ddf463e5e9ec144b" + "777de62aaab8a8628ac376d282d6ed3864e67982428ebc83"
        + "1d14348f6f2f9193b5045af2767164e1dfc967c1fb3f2e55" + "a4bd1bffe83b9c80d052b985d182ea0adb2a3b7313d3fe14"
        + "c8484b1e052588b9b7d2bbd2df016199ecd06e1557cd0915" + "b3353bbb64e0ec377fd028370df92b52c7891428cdc67eb6"
        + "184b523d1db246c32f63078490f00ef8d647d148d4795451" + "5e2327cfef98c582664b4c0f6cc41659";
    private static final string rfc5114_2048_256_q = "8cf83642a709a097b447997640129da299b1a47d1eb3750b"
        + "a308b0fe64f5fbd3";
    public static final dhparameters rfc5114_2048_256 = frompgq(rfc5114_2048_256_p, rfc5114_2048_256_g,
        rfc5114_2048_256_q);

    /*
     * rfc 5996
     */
    public static final dhparameters rfc5996_768 = rfc4306_768;
    public static final dhparameters rfc5996_1024 = rfc4306_1024;
}
