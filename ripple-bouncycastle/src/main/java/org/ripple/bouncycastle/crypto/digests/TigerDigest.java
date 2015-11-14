package org.ripple.bouncycastle.crypto.digests;

import org.ripple.bouncycastle.crypto.extendeddigest;
import org.ripple.bouncycastle.util.memoable;

/**
 * implementation of tiger based on:
 * <a href="http://www.cs.technion.ac.il/~biham/reports/tiger">
 *  http://www.cs.technion.ac.il/~biham/reports/tiger</a>
 */
public class tigerdigest
    implements extendeddigest, memoable
{
    private static final int byte_length = 64;
    
    /*
     * s-boxes.
     */
    private static final long[] t1 = {
        0x02aab17cf7e90c5el   /*    0 */,    0xac424b03e243a8ecl   /*    1 */,
        0x72cd5be30dd5fcd3l   /*    2 */,    0x6d019b93f6f97f3al   /*    3 */,
        0xcd9978ffd21f9193l   /*    4 */,    0x7573a1c9708029e2l   /*    5 */,
        0xb164326b922a83c3l   /*    6 */,    0x46883eee04915870l   /*    7 */,
        0xeaace3057103ece6l   /*    8 */,    0xc54169b808a3535cl   /*    9 */,
        0x4ce754918ddec47cl   /*   10 */,    0x0aa2f4dfdc0df40cl   /*   11 */,
        0x10b76f18a74dbefal   /*   12 */,    0xc6ccb6235ad1ab6al   /*   13 */,
        0x13726121572fe2ffl   /*   14 */,    0x1a488c6f199d921el   /*   15 */,
        0x4bc9f9f4da0007cal   /*   16 */,    0x26f5e6f6e85241c7l   /*   17 */,
        0x859079dbea5947b6l   /*   18 */,    0x4f1885c5c99e8c92l   /*   19 */,
        0xd78e761ea96f864bl   /*   20 */,    0x8e36428c52b5c17dl   /*   21 */,
        0x69cf6827373063c1l   /*   22 */,    0xb607c93d9bb4c56el   /*   23 */,
        0x7d820e760e76b5eal   /*   24 */,    0x645c9cc6f07fdc42l   /*   25 */,
        0xbf38a078243342e0l   /*   26 */,    0x5f6b343c9d2e7d04l   /*   27 */,
        0xf2c28aeb600b0ec6l   /*   28 */,    0x6c0ed85f7254bcacl   /*   29 */,
        0x71592281a4db4fe5l   /*   30 */,    0x1967fa69ce0fed9fl   /*   31 */,
        0xfd5293f8b96545dbl   /*   32 */,    0xc879e9d7f2a7600bl   /*   33 */,
        0x860248920193194el   /*   34 */,    0xa4f9533b2d9cc0b3l   /*   35 */,
        0x9053836c15957613l   /*   36 */,    0xdb6dcf8afc357bf1l   /*   37 */,
        0x18beea7a7a370f57l   /*   38 */,    0x037117ca50b99066l   /*   39 */,
        0x6ab30a9774424a35l   /*   40 */,    0xf4e92f02e325249bl   /*   41 */,
        0x7739db07061ccae1l   /*   42 */,    0xd8f3b49ceca42a05l   /*   43 */,
        0xbd56be3f51382f73l   /*   44 */,    0x45faed5843b0bb28l   /*   45 */,
        0x1c813d5c11bf1f83l   /*   46 */,    0x8af0e4b6d75fa169l   /*   47 */,
        0x33ee18a487ad9999l   /*   48 */,    0x3c26e8eab1c94410l   /*   49 */,
        0xb510102bc0a822f9l   /*   50 */,    0x141eef310ce6123bl   /*   51 */,
        0xfc65b90059ddb154l   /*   52 */,    0xe0158640c5e0e607l   /*   53 */,
        0x884e079826c3a3cfl   /*   54 */,    0x930d0d9523c535fdl   /*   55 */,
        0x35638d754e9a2b00l   /*   56 */,    0x4085fccf40469dd5l   /*   57 */,
        0xc4b17ad28be23a4cl   /*   58 */,    0xcab2f0fc6a3e6a2el   /*   59 */,
        0x2860971a6b943fcdl   /*   60 */,    0x3dde6ee212e30446l   /*   61 */,
        0x6222f32ae01765ael   /*   62 */,    0x5d550bb5478308fel   /*   63 */,
        0xa9efa98da0eda22al   /*   64 */,    0xc351a71686c40da7l   /*   65 */,
        0x1105586d9c867c84l   /*   66 */,    0xdcffee85fda22853l   /*   67 */,
        0xccfbd0262c5eef76l   /*   68 */,    0xbaf294cb8990d201l   /*   69 */,
        0xe69464f52afad975l   /*   70 */,    0x94b013afdf133e14l   /*   71 */,
        0x06a7d1a32823c958l   /*   72 */,    0x6f95fe5130f61119l   /*   73 */,
        0xd92ab34e462c06c0l   /*   74 */,    0xed7bde33887c71d2l   /*   75 */,
        0x79746d6e6518393el   /*   76 */,    0x5ba419385d713329l   /*   77 */,
        0x7c1ba6b948a97564l   /*   78 */,    0x31987c197bfdac67l   /*   79 */,
        0xde6c23c44b053d02l   /*   80 */,    0x581c49fed002d64dl   /*   81 */,
        0xdd474d6338261571l   /*   82 */,    0xaa4546c3e473d062l   /*   83 */,
        0x928fce349455f860l   /*   84 */,    0x48161bbacaab94d9l   /*   85 */,
        0x63912430770e6f68l   /*   86 */,    0x6ec8a5e602c6641cl   /*   87 */,
        0x87282515337ddd2bl   /*   88 */,    0x2cda6b42034b701bl   /*   89 */,
        0xb03d37c181cb096dl   /*   90 */,    0xe108438266c71c6fl   /*   91 */,
        0x2b3180c7eb51b255l   /*   92 */,    0xdf92b82f96c08bbcl   /*   93 */,
        0x5c68c8c0a632f3bal   /*   94 */,    0x5504cc861c3d0556l   /*   95 */,
        0xabbfa4e55fb26b8fl   /*   96 */,    0x41848b0ab3baceb4l   /*   97 */,
        0xb334a273aa445d32l   /*   98 */,    0xbca696f0a85ad881l   /*   99 */,
        0x24f6ec65b528d56cl   /*  100 */,    0x0ce1512e90f4524al   /*  101 */,
        0x4e9dd79d5506d35al   /*  102 */,    0x258905fac6ce9779l   /*  103 */,
        0x2019295b3e109b33l   /*  104 */,    0xf8a9478b73a054ccl   /*  105 */,
        0x2924f2f934417eb0l   /*  106 */,    0x3993357d536d1bc4l   /*  107 */,
        0x38a81ac21db6ff8bl   /*  108 */,    0x47c4fbf17d6016bfl   /*  109 */,
        0x1e0faadd7667e3f5l   /*  110 */,    0x7abcff62938beb96l   /*  111 */,
        0xa78dad948fc179c9l   /*  112 */,    0x8f1f98b72911e50dl   /*  113 */,
        0x61e48eae27121a91l   /*  114 */,    0x4d62f7ad31859808l   /*  115 */,
        0xeceba345ef5ceaebl   /*  116 */,    0xf5ceb25ebc9684cel   /*  117 */,
        0xf633e20cb7f76221l   /*  118 */,    0xa32cdf06ab8293e4l   /*  119 */,
        0x985a202ca5ee2ca4l   /*  120 */,    0xcf0b8447cc8a8fb1l   /*  121 */,
        0x9f765244979859a3l   /*  122 */,    0xa8d516b1a1240017l   /*  123 */,
        0x0bd7ba3ebb5dc726l   /*  124 */,    0xe54bca55b86adb39l   /*  125 */,
        0x1d7a3afd6c478063l   /*  126 */,    0x519ec608e7669eddl   /*  127 */,
        0x0e5715a2d149aa23l   /*  128 */,    0x177d4571848ff194l   /*  129 */,
        0xeeb55f3241014c22l   /*  130 */,    0x0f5e5ca13a6e2ec2l   /*  131 */,
        0x8029927b75f5c361l   /*  132 */,    0xad139fabc3d6e436l   /*  133 */,
        0x0d5df1a94ccf402fl   /*  134 */,    0x3e8bd948bea5dfc8l   /*  135 */,
        0xa5a0d357bd3ff77el   /*  136 */,    0xa2d12e251f74f645l   /*  137 */,
        0x66fd9e525e81a082l   /*  138 */,    0x2e0c90ce7f687a49l   /*  139 */,
        0xc2e8bcbeba973bc5l   /*  140 */,    0x000001bce509745fl   /*  141 */,
        0x423777bbe6dab3d6l   /*  142 */,    0xd1661c7eaef06eb5l   /*  143 */,
        0xa1781f354daacfd8l   /*  144 */,    0x2d11284a2b16affcl   /*  145 */,
        0xf1fc4f67fa891d1fl   /*  146 */,    0x73ecc25dcb920adal   /*  147 */,
        0xae610c22c2a12651l   /*  148 */,    0x96e0a810d356b78al   /*  149 */,
        0x5a9a381f2fe7870fl   /*  150 */,    0xd5ad62ede94e5530l   /*  151 */,
        0xd225e5e8368d1427l   /*  152 */,    0x65977b70c7af4631l   /*  153 */,
        0x99f889b2de39d74fl   /*  154 */,    0x233f30bf54e1d143l   /*  155 */,
        0x9a9675d3d9a63c97l   /*  156 */,    0x5470554ff334f9a8l   /*  157 */,
        0x166acb744a4f5688l   /*  158 */,    0x70c74caab2e4aeadl   /*  159 */,
        0xf0d091646f294d12l   /*  160 */,    0x57b82a89684031d1l   /*  161 */,
        0xefd95a5a61be0b6bl   /*  162 */,    0x2fbd12e969f2f29al   /*  163 */,
        0x9bd37013feff9fe8l   /*  164 */,    0x3f9b0404d6085a06l   /*  165 */,
        0x4940c1f3166cfe15l   /*  166 */,    0x09542c4dcdf3defbl   /*  167 */,
        0xb4c5218385cd5ce3l   /*  168 */,    0xc935b7dc4462a641l   /*  169 */,
        0x3417f8a68ed3b63fl   /*  170 */,    0xb80959295b215b40l   /*  171 */,
        0xf99cdaef3b8c8572l   /*  172 */,    0x018c0614f8fcb95dl   /*  173 */,
        0x1b14accd1a3acdf3l   /*  174 */,    0x84d471f200bb732dl   /*  175 */,
        0xc1a3110e95e8da16l   /*  176 */,    0x430a7220bf1a82b8l   /*  177 */,
        0xb77e090d39df210el   /*  178 */,    0x5ef4bd9f3cd05e9dl   /*  179 */,
        0x9d4ff6da7e57a444l   /*  180 */,    0xda1d60e183d4a5f8l   /*  181 */,
        0xb287c38417998e47l   /*  182 */,    0xfe3edc121bb31886l   /*  183 */,
        0xc7fe3ccc980ccbefl   /*  184 */,    0xe46fb590189bfd03l   /*  185 */,
        0x3732fd469a4c57dcl   /*  186 */,    0x7ef700a07cf1ad65l   /*  187 */,
        0x59c64468a31d8859l   /*  188 */,    0x762fb0b4d45b61f6l   /*  189 */,
        0x155baed099047718l   /*  190 */,    0x68755e4c3d50baa6l   /*  191 */,
        0xe9214e7f22d8b4dfl   /*  192 */,    0x2addbf532eac95f4l   /*  193 */,
        0x32ae3909b4bd0109l   /*  194 */,    0x834df537b08e3450l   /*  195 */,
        0xfa209da84220728dl   /*  196 */,    0x9e691d9b9efe23f7l   /*  197 */,
        0x0446d288c4ae8d7fl   /*  198 */,    0x7b4cc524e169785bl   /*  199 */,
        0x21d87f0135ca1385l   /*  200 */,    0xcebb400f137b8aa5l   /*  201 */,
        0x272e2b66580796bel   /*  202 */,    0x3612264125c2b0del   /*  203 */,
        0x057702bdad1efbb2l   /*  204 */,    0xd4babb8eacf84be9l   /*  205 */,
        0x91583139641bc67bl   /*  206 */,    0x8bdc2de08036e024l   /*  207 */,
        0x603c8156f49f68edl   /*  208 */,    0xf7d236f7dbef5111l   /*  209 */,
        0x9727c4598ad21e80l   /*  210 */,    0xa08a0896670a5fd7l   /*  211 */,
        0xcb4a8f4309eba9cbl   /*  212 */,    0x81af564b0f7036a1l   /*  213 */,
        0xc0b99aa778199abdl   /*  214 */,    0x959f1ec83fc8e952l   /*  215 */,
        0x8c505077794a81b9l   /*  216 */,    0x3acaaf8f056338f0l   /*  217 */,
        0x07b43f50627a6778l   /*  218 */,    0x4a44ab49f5eccc77l   /*  219 */,
        0x3bc3d6e4b679ee98l   /*  220 */,    0x9cc0d4d1cf14108cl   /*  221 */,
        0x4406c00b206bc8a0l   /*  222 */,    0x82a18854c8d72d89l   /*  223 */,
        0x67e366b35c3c432cl   /*  224 */,    0xb923dd61102b37f2l   /*  225 */,
        0x56ab2779d884271dl   /*  226 */,    0xbe83e1b0ff1525afl   /*  227 */,
        0xfb7c65d4217e49a9l   /*  228 */,    0x6bdbe0e76d48e7d4l   /*  229 */,
        0x08df828745d9179el   /*  230 */,    0x22ea6a9add53bd34l   /*  231 */,
        0xe36e141c5622200al   /*  232 */,    0x7f805d1b8cb750eel   /*  233 */,
        0xafe5c7a59f58e837l   /*  234 */,    0xe27f996a4fb1c23cl   /*  235 */,
        0xd3867dfb0775f0d0l   /*  236 */,    0xd0e673de6e88891al   /*  237 */,
        0x123aeb9eafb86c25l   /*  238 */,    0x30f1d5d5c145b895l   /*  239 */,
        0xbb434a2dee7269e7l   /*  240 */,    0x78cb67ecf931fa38l   /*  241 */,
        0xf33b0372323bbf9cl   /*  242 */,    0x52d66336fb279c74l   /*  243 */,
        0x505f33ac0afb4eaal   /*  244 */,    0xe8a5cd99a2cce187l   /*  245 */,
        0x534974801e2d30bbl   /*  246 */,    0x8d2d5711d5876d90l   /*  247 */,
        0x1f1a412891bc038el   /*  248 */,    0xd6e2e71d82e56648l   /*  249 */,
        0x74036c3a497732b7l   /*  250 */,    0x89b67ed96361f5abl   /*  251 */,
        0xffed95d8f1ea02a2l   /*  252 */,    0xe72b3bd61464d43dl   /*  253 */,
        0xa6300f170bdc4820l   /*  254 */,    0xebc18760ed78a77al   /*  255 */,
    };

    private static final long[] t2 = {
        0xe6a6be5a05a12138l   /*  256 */,    0xb5a122a5b4f87c98l   /*  257 */,
        0x563c6089140b6990l   /*  258 */,    0x4c46cb2e391f5dd5l   /*  259 */,
        0xd932addbc9b79434l   /*  260 */,    0x08ea70e42015aff5l   /*  261 */,
        0xd765a6673e478cf1l   /*  262 */,    0xc4fb757eab278d99l   /*  263 */,
        0xdf11c6862d6e0692l   /*  264 */,    0xddeb84f10d7f3b16l   /*  265 */,
        0x6f2ef604a665ea04l   /*  266 */,    0x4a8e0f0ff0e0dfb3l   /*  267 */,
        0xa5edeef83dbcba51l   /*  268 */,    0xfc4f0a2a0ea4371el   /*  269 */,
        0xe83e1da85cb38429l   /*  270 */,    0xdc8ff882ba1b1ce2l   /*  271 */,
        0xcd45505e8353e80dl   /*  272 */,    0x18d19a00d4db0717l   /*  273 */,
        0x34a0cfeda5f38101l   /*  274 */,    0x0be77e518887caf2l   /*  275 */,
        0x1e341438b3c45136l   /*  276 */,    0xe05797f49089ccf9l   /*  277 */,
        0xffd23f9df2591d14l   /*  278 */,    0x543dda228595c5cdl   /*  279 */,
        0x661f81fd99052a33l   /*  280 */,    0x8736e641db0f7b76l   /*  281 */,
        0x15227725418e5307l   /*  282 */,    0xe25f7f46162eb2fal   /*  283 */,
        0x48a8b2126c13d9fel   /*  284 */,    0xafdc541792e76eeal   /*  285 */,
        0x03d912bfc6d1898fl   /*  286 */,    0x31b1aafa1b83f51bl   /*  287 */,
        0xf1ac2796e42ab7d9l   /*  288 */,    0x40a3a7d7fcd2ebacl   /*  289 */,
        0x1056136d0afbbcc5l   /*  290 */,    0x7889e1dd9a6d0c85l   /*  291 */,
        0xd33525782a7974aal   /*  292 */,    0xa7e25d09078ac09bl   /*  293 */,
        0xbd4138b3eac6edd0l   /*  294 */,    0x920abfbe71eb9e70l   /*  295 */,
        0xa2a5d0f54fc2625cl   /*  296 */,    0xc054e36b0b1290a3l   /*  297 */,
        0xf6dd59ff62fe932bl   /*  298 */,    0x3537354511a8ac7dl   /*  299 */,
        0xca845e9172fadcd4l   /*  300 */,    0x84f82b60329d20dcl   /*  301 */,
        0x79c62ce1cd672f18l   /*  302 */,    0x8b09a2add124642cl   /*  303 */,
        0xd0c1e96a19d9e726l   /*  304 */,    0x5a786a9b4ba9500cl   /*  305 */,
        0x0e020336634c43f3l   /*  306 */,    0xc17b474aeb66d822l   /*  307 */,
        0x6a731ae3ec9baac2l   /*  308 */,    0x8226667ae0840258l   /*  309 */,
        0x67d4567691caeca5l   /*  310 */,    0x1d94155c4875adb5l   /*  311 */,
        0x6d00fd985b813fdfl   /*  312 */,    0x51286efcb774cd06l   /*  313 */,
        0x5e8834471fa744afl   /*  314 */,    0xf72ca0aee761ae2el   /*  315 */,
        0xbe40e4cdaee8e09al   /*  316 */,    0xe9970bbb5118f665l   /*  317 */,
        0x726e4beb33df1964l   /*  318 */,    0x703b000729199762l   /*  319 */,
        0x4631d816f5ef30a7l   /*  320 */,    0xb880b5b51504a6bel   /*  321 */,
        0x641793c37ed84b6cl   /*  322 */,    0x7b21ed77f6e97d96l   /*  323 */,
        0x776306312ef96b73l   /*  324 */,    0xae528948e86ff3f4l   /*  325 */,
        0x53dbd7f286a3f8f8l   /*  326 */,    0x16cadce74cfc1063l   /*  327 */,
        0x005c19bdfa52c6ddl   /*  328 */,    0x68868f5d64d46ad3l   /*  329 */,
        0x3a9d512ccf1e186al   /*  330 */,    0x367e62c2385660ael   /*  331 */,
        0xe359e7ea77dcb1d7l   /*  332 */,    0x526c0773749abe6el   /*  333 */,
        0x735ae5f9d09f734bl   /*  334 */,    0x493fc7cc8a558ba8l   /*  335 */,
        0xb0b9c1533041ab45l   /*  336 */,    0x321958ba470a59bdl   /*  337 */,
        0x852db00b5f46c393l   /*  338 */,    0x91209b2bd336b0e5l   /*  339 */,
        0x6e604f7d659ef19fl   /*  340 */,    0xb99a8ae2782ccb24l   /*  341 */,
        0xccf52ab6c814c4c7l   /*  342 */,    0x4727d9afbe11727bl   /*  343 */,
        0x7e950d0c0121b34dl   /*  344 */,    0x756f435670ad471fl   /*  345 */,
        0xf5add442615a6849l   /*  346 */,    0x4e87e09980b9957al   /*  347 */,
        0x2acfa1df50aee355l   /*  348 */,    0xd898263afd2fd556l   /*  349 */,
        0xc8f4924dd80c8fd6l   /*  350 */,    0xcf99ca3d754a173al   /*  351 */,
        0xfe477bacaf91bf3cl   /*  352 */,    0xed5371f6d690c12dl   /*  353 */,
        0x831a5c285e687094l   /*  354 */,    0xc5d3c90a3708a0a4l   /*  355 */,
        0x0f7f903717d06580l   /*  356 */,    0x19f9bb13b8fdf27fl   /*  357 */,
        0xb1bd6f1b4d502843l   /*  358 */,    0x1c761ba38fff4012l   /*  359 */,
        0x0d1530c4e2e21f3bl   /*  360 */,    0x8943ce69a7372c8al   /*  361 */,
        0xe5184e11feb5ce66l   /*  362 */,    0x618bdb80bd736621l   /*  363 */,
        0x7d29bad68b574d0bl   /*  364 */,    0x81bb613e25e6fe5bl   /*  365 */,
        0x071c9c10bc07913fl   /*  366 */,    0xc7beeb7909ac2d97l   /*  367 */,
        0xc3e58d353bc5d757l   /*  368 */,    0xeb017892f38f61e8l   /*  369 */,
        0xd4effb9c9b1cc21al   /*  370 */,    0x99727d26f494f7abl   /*  371 */,
        0xa3e063a2956b3e03l   /*  372 */,    0x9d4a8b9a4aa09c30l   /*  373 */,
        0x3f6ab7d500090fb4l   /*  374 */,    0x9cc0f2a057268ac0l   /*  375 */,
        0x3dee9d2dedbf42d1l   /*  376 */,    0x330f49c87960a972l   /*  377 */,
        0xc6b2720287421b41l   /*  378 */,    0x0ac59ec07c00369cl   /*  379 */,
        0xef4eac49cb353425l   /*  380 */,    0xf450244eef0129d8l   /*  381 */,
        0x8acc46e5caf4deb6l   /*  382 */,    0x2ffeab63989263f7l   /*  383 */,
        0x8f7cb9fe5d7a4578l   /*  384 */,    0x5bd8f7644e634635l   /*  385 */,
        0x427a7315bf2dc900l   /*  386 */,    0x17d0c4aa2125261cl   /*  387 */,
        0x3992486c93518e50l   /*  388 */,    0xb4cbfee0a2d7d4c3l   /*  389 */,
        0x7c75d6202c5ddd8dl   /*  390 */,    0xdbc295d8e35b6c61l   /*  391 */,
        0x60b369d302032b19l   /*  392 */,    0xce42685fdce44132l   /*  393 */,
        0x06f3ddb9ddf65610l   /*  394 */,    0x8ea4d21db5e148f0l   /*  395 */,
        0x20b0fce62fcd496fl   /*  396 */,    0x2c1b912358b0ee31l   /*  397 */,
        0xb28317b818f5a308l   /*  398 */,    0xa89c1e189ca6d2cfl   /*  399 */,
        0x0c6b18576aaadbc8l   /*  400 */,    0xb65deaa91299fae3l   /*  401 */,
        0xfb2b794b7f1027e7l   /*  402 */,    0x04e4317f443b5bebl   /*  403 */,
        0x4b852d325939d0a6l   /*  404 */,    0xd5ae6beefb207ffcl   /*  405 */,
        0x309682b281c7d374l   /*  406 */,    0xbae309a194c3b475l   /*  407 */,
        0x8cc3f97b13b49f05l   /*  408 */,    0x98a9422ff8293967l   /*  409 */,
        0x244b16b01076ff7cl   /*  410 */,    0xf8bf571c663d67eel   /*  411 */,
        0x1f0d6758eee30da1l   /*  412 */,    0xc9b611d97adeb9b7l   /*  413 */,
        0xb7afd5887b6c57a2l   /*  414 */,    0x6290ae846b984fe1l   /*  415 */,
        0x94df4cdeacc1a5fdl   /*  416 */,    0x058a5bd1c5483affl   /*  417 */,
        0x63166cc142ba3c37l   /*  418 */,    0x8db8526eb2f76f40l   /*  419 */,
        0xe10880036f0d6d4el   /*  420 */,    0x9e0523c9971d311dl   /*  421 */,
        0x45ec2824cc7cd691l   /*  422 */,    0x575b8359e62382c9l   /*  423 */,
        0xfa9e400dc4889995l   /*  424 */,    0xd1823ecb45721568l   /*  425 */,
        0xdafd983b8206082fl   /*  426 */,    0xaa7d29082386a8cbl   /*  427 */,
        0x269fcd4403b87588l   /*  428 */,    0x1b91f5f728bdd1e0l   /*  429 */,
        0xe4669f39040201f6l   /*  430 */,    0x7a1d7c218cf04adel   /*  431 */,
        0x65623c29d79ce5cel   /*  432 */,    0x2368449096c00bb1l   /*  433 */,
        0xab9bf1879da503bal   /*  434 */,    0xbc23ecb1a458058el   /*  435 */,
        0x9a58df01bb401eccl   /*  436 */,    0xa070e868a85f143dl   /*  437 */,
        0x4ff188307df2239el   /*  438 */,    0x14d565b41a641183l   /*  439 */,
        0xee13337452701602l   /*  440 */,    0x950e3dcf3f285e09l   /*  441 */,
        0x59930254b9c80953l   /*  442 */,    0x3bf299408930da6dl   /*  443 */,
        0xa955943f53691387l   /*  444 */,    0xa15edecaa9cb8784l   /*  445 */,
        0x29142127352be9a0l   /*  446 */,    0x76f0371fff4e7afbl   /*  447 */,
        0x0239f450274f2228l   /*  448 */,    0xbb073af01d5e868bl   /*  449 */,
        0xbfc80571c10e96c1l   /*  450 */,    0xd267088568222e23l   /*  451 */,
        0x9671a3d48e80b5b0l   /*  452 */,    0x55b5d38ae193bb81l   /*  453 */,
        0x693ae2d0a18b04b8l   /*  454 */,    0x5c48b4ecadd5335fl   /*  455 */,
        0xfd743b194916a1cal   /*  456 */,    0x2577018134be98c4l   /*  457 */,
        0xe77987e83c54a4adl   /*  458 */,    0x28e11014da33e1b9l   /*  459 */,
        0x270cc59e226aa213l   /*  460 */,    0x71495f756d1a5f60l   /*  461 */,
        0x9be853fb60afef77l   /*  462 */,    0xadc786a7f7443dbfl   /*  463 */,
        0x0904456173b29a82l   /*  464 */,    0x58bc7a66c232bd5el   /*  465 */,
        0xf306558c673ac8b2l   /*  466 */,    0x41f639c6b6c9772al   /*  467 */,
        0x216defe99fda35dal   /*  468 */,    0x11640cc71c7be615l   /*  469 */,
        0x93c43694565c5527l   /*  470 */,    0xea038e6246777839l   /*  471 */,
        0xf9abf3ce5a3e2469l   /*  472 */,    0x741e768d0fd312d2l   /*  473 */,
        0x0144b883ced652c6l   /*  474 */,    0xc20b5a5ba33f8552l   /*  475 */,
        0x1ae69633c3435a9dl   /*  476 */,    0x97a28ca4088cfdecl   /*  477 */,
        0x8824a43c1e96f420l   /*  478 */,    0x37612fa66eeea746l   /*  479 */,
        0x6b4cb165f9cf0e5al   /*  480 */,    0x43aa1c06a0abfb4al   /*  481 */,
        0x7f4dc26ff162796bl   /*  482 */,    0x6cbacc8e54ed9b0fl   /*  483 */,
        0xa6b7ffefd2bb253el   /*  484 */,    0x2e25bc95b0a29d4fl   /*  485 */,
        0x86d6a58bdef1388cl   /*  486 */,    0xded74ac576b6f054l   /*  487 */,
        0x8030bdbc2b45805dl   /*  488 */,    0x3c81af70e94d9289l   /*  489 */,
        0x3eff6dda9e3100dbl   /*  490 */,    0xb38dc39fdfcc8847l   /*  491 */,
        0x123885528d17b87el   /*  492 */,    0xf2da0ed240b1b642l   /*  493 */,
        0x44cefadcd54bf9a9l   /*  494 */,    0x1312200e433c7ee6l   /*  495 */,
        0x9ffcc84f3a78c748l   /*  496 */,    0xf0cd1f72248576bbl   /*  497 */,
        0xec6974053638cfe4l   /*  498 */,    0x2ba7b67c0cec4e4cl   /*  499 */,
        0xac2f4df3e5ce32edl   /*  500 */,    0xcb33d14326ea4c11l   /*  501 */,
        0xa4e9044cc77e58bcl   /*  502 */,    0x5f513293d934fcefl   /*  503 */,
        0x5dc9645506e55444l   /*  504 */,    0x50de418f317de40al   /*  505 */,
        0x388cb31a69dde259l   /*  506 */,    0x2db4a83455820a86l   /*  507 */,
        0x9010a91e84711ae9l   /*  508 */,    0x4df7f0b7b1498371l   /*  509 */,
        0xd62a2eabc0977179l   /*  510 */,    0x22fac097aa8d5c0el   /*  511 */,
    };

    private static final long[] t3 = {
        0xf49fcc2ff1daf39bl   /*  512 */,    0x487fd5c66ff29281l   /*  513 */,
        0xe8a30667fcdca83fl   /*  514 */,    0x2c9b4be3d2fcce63l   /*  515 */,
        0xda3ff74b93fbbbc2l   /*  516 */,    0x2fa165d2fe70ba66l   /*  517 */,
        0xa103e279970e93d4l   /*  518 */,    0xbecdec77b0e45e71l   /*  519 */,
        0xcfb41e723985e497l   /*  520 */,    0xb70aaa025ef75017l   /*  521 */,
        0xd42309f03840b8e0l   /*  522 */,    0x8efc1ad035898579l   /*  523 */,
        0x96c6920be2b2abc5l   /*  524 */,    0x66af4163375a9172l   /*  525 */,
        0x2174abdcca7127fbl   /*  526 */,    0xb33ccea64a72ff41l   /*  527 */,
        0xf04a4933083066a5l   /*  528 */,    0x8d970acdd7289af5l   /*  529 */,
        0x8f96e8e031c8c25el   /*  530 */,    0xf3fec02276875d47l   /*  531 */,
        0xec7bf310056190ddl   /*  532 */,    0xf5adb0aebb0f1491l   /*  533 */,
        0x9b50f8850fd58892l   /*  534 */,    0x4975488358b74de8l   /*  535 */,
        0xa3354ff691531c61l   /*  536 */,    0x0702bbe481d2c6eel   /*  537 */,
        0x89fb24057deded98l   /*  538 */,    0xac3075138596e902l   /*  539 */,
        0x1d2d3580172772edl   /*  540 */,    0xeb738fc28e6bc30dl   /*  541 */,
        0x5854ef8f63044326l   /*  542 */,    0x9e5c52325add3bbel   /*  543 */,
        0x90aa53cf325c4623l   /*  544 */,    0xc1d24d51349dd067l   /*  545 */,
        0x2051cfeea69ea624l   /*  546 */,    0x13220f0a862e7e4fl   /*  547 */,
        0xce39399404e04864l   /*  548 */,    0xd9c42ca47086fcb7l   /*  549 */,
        0x685ad2238a03e7ccl   /*  550 */,    0x066484b2ab2ff1dbl   /*  551 */,
        0xfe9d5d70efbf79ecl   /*  552 */,    0x5b13b9dd9c481854l   /*  553 */,
        0x15f0d475ed1509adl   /*  554 */,    0x0bebcd060ec79851l   /*  555 */,
        0xd58c6791183ab7f8l   /*  556 */,    0xd1187c5052f3eee4l   /*  557 */,
        0xc95d1192e54e82ffl   /*  558 */,    0x86eea14cb9ac6ca2l   /*  559 */,
        0x3485beb153677d5dl   /*  560 */,    0xdd191d781f8c492al   /*  561 */,
        0xf60866baa784ebf9l   /*  562 */,    0x518f643ba2d08c74l   /*  563 */,
        0x8852e956e1087c22l   /*  564 */,    0xa768cb8dc410ae8dl   /*  565 */,
        0x38047726bfec8e1al   /*  566 */,    0xa67738b4cd3b45aal   /*  567 */,
        0xad16691cec0dde19l   /*  568 */,    0xc6d4319380462e07l   /*  569 */,
        0xc5a5876d0ba61938l   /*  570 */,    0x16b9fa1fa58fd840l   /*  571 */,
        0x188ab1173ca74f18l   /*  572 */,    0xabda2f98c99c021fl   /*  573 */,
        0x3e0580ab134ae816l   /*  574 */,    0x5f3b05b773645abbl   /*  575 */,
        0x2501a2be5575f2f6l   /*  576 */,    0x1b2f74004e7e8ba9l   /*  577 */,
        0x1cd7580371e8d953l   /*  578 */,    0x7f6ed89562764e30l   /*  579 */,
        0xb15926ff596f003dl   /*  580 */,    0x9f65293da8c5d6b9l   /*  581 */,
        0x6ecef04dd690f84cl   /*  582 */,    0x4782275fff33af88l   /*  583 */,
        0xe41433083f820801l   /*  584 */,    0xfd0dfe409a1af9b5l   /*  585 */,
        0x4325a3342cdb396bl   /*  586 */,    0x8ae77e62b301b252l   /*  587 */,
        0xc36f9e9f6655615al   /*  588 */,    0x85455a2d92d32c09l   /*  589 */,
        0xf2c7dea949477485l   /*  590 */,    0x63cfb4c133a39ebal   /*  591 */,
        0x83b040cc6ebc5462l   /*  592 */,    0x3b9454c8fdb326b0l   /*  593 */,
        0x56f56a9e87ffd78cl   /*  594 */,    0x2dc2940d99f42bc6l   /*  595 */,
        0x98f7df096b096e2dl   /*  596 */,    0x19a6e01e3ad852bfl   /*  597 */,
        0x42a99ccbdbd4b40bl   /*  598 */,    0xa59998af45e9c559l   /*  599 */,
        0x366295e807d93186l   /*  600 */,    0x6b48181bfaa1f773l   /*  601 */,
        0x1fec57e2157a0a1dl   /*  602 */,    0x4667446af6201ad5l   /*  603 */,
        0xe615ebcacfb0f075l   /*  604 */,    0xb8f31f4f68290778l   /*  605 */,
        0x22713ed6ce22d11el   /*  606 */,    0x3057c1a72ec3c93bl   /*  607 */,
        0xcb46acc37c3f1f2fl   /*  608 */,    0xdbb893fd02aaf50el   /*  609 */,
        0x331fd92e600b9fcfl   /*  610 */,    0xa498f96148ea3ad6l   /*  611 */,
        0xa8d8426e8b6a83eal   /*  612 */,    0xa089b274b7735cdcl   /*  613 */,
        0x87f6b3731e524a11l   /*  614 */,    0x118808e5cbc96749l   /*  615 */,
        0x9906e4c7b19bd394l   /*  616 */,    0xafed7f7e9b24a20cl   /*  617 */,
        0x6509eadeeb3644a7l   /*  618 */,    0x6c1ef1d3e8ef0edel   /*  619 */,
        0xb9c97d43e9798fb4l   /*  620 */,    0xa2f2d784740c28a3l   /*  621 */,
        0x7b8496476197566fl   /*  622 */,    0x7a5be3e6b65f069dl   /*  623 */,
        0xf96330ed78be6f10l   /*  624 */,    0xeee60de77a076a15l   /*  625 */,
        0x2b4bee4aa08b9bd0l   /*  626 */,    0x6a56a63ec7b8894el   /*  627 */,
        0x02121359ba34fef4l   /*  628 */,    0x4cbf99f8283703fcl   /*  629 */,
        0x398071350caf30c8l   /*  630 */,    0xd0a77a89f017687al   /*  631 */,
        0xf1c1a9eb9e423569l   /*  632 */,    0x8c7976282dee8199l   /*  633 */,
        0x5d1737a5dd1f7abdl   /*  634 */,    0x4f53433c09a9fa80l   /*  635 */,
        0xfa8b0c53df7ca1d9l   /*  636 */,    0x3fd9dcbc886ccb77l   /*  637 */,
        0xc040917ca91b4720l   /*  638 */,    0x7dd00142f9d1dcdfl   /*  639 */,
        0x8476fc1d4f387b58l   /*  640 */,    0x23f8e7c5f3316503l   /*  641 */,
        0x032a2244e7e37339l   /*  642 */,    0x5c87a5d750f5a74bl   /*  643 */,
        0x082b4cc43698992el   /*  644 */,    0xdf917becb858f63cl   /*  645 */,
        0x3270b8fc5bf86ddal   /*  646 */,    0x10ae72bb29b5dd76l   /*  647 */,
        0x576ac94e7700362bl   /*  648 */,    0x1ad112dac61efb8fl   /*  649 */,
        0x691bc30ec5faa427l   /*  650 */,    0xff246311cc327143l   /*  651 */,
        0x3142368e30e53206l   /*  652 */,    0x71380e31e02ca396l   /*  653 */,
        0x958d5c960aad76f1l   /*  654 */,    0xf8d6f430c16da536l   /*  655 */,
        0xc8ffd13f1be7e1d2l   /*  656 */,    0x7578ae66004ddbe1l   /*  657 */,
        0x05833f01067be646l   /*  658 */,    0xbb34b5ad3bfe586dl   /*  659 */,
        0x095f34c9a12b97f0l   /*  660 */,    0x247ab64525d60ca8l   /*  661 */,
        0xdcdbc6f3017477d1l   /*  662 */,    0x4a2e14d4decad24dl   /*  663 */,
        0xbdb5e6d9be0a1eebl   /*  664 */,    0x2a7e70f7794301abl   /*  665 */,
        0xdef42d8a270540fdl   /*  666 */,    0x01078ec0a34c22c1l   /*  667 */,
        0xe5de511af4c16387l   /*  668 */,    0x7ebb3a52bd9a330al   /*  669 */,
        0x77697857aa7d6435l   /*  670 */,    0x004e831603ae4c32l   /*  671 */,
        0xe7a21020ad78e312l   /*  672 */,    0x9d41a70c6ab420f2l   /*  673 */,
        0x28e06c18ea1141e6l   /*  674 */,    0xd2b28cbd984f6b28l   /*  675 */,
        0x26b75f6c446e9d83l   /*  676 */,    0xba47568c4d418d7fl   /*  677 */,
        0xd80badbfe6183d8el   /*  678 */,    0x0e206d7f5f166044l   /*  679 */,
        0xe258a43911cbca3el   /*  680 */,    0x723a1746b21dc0bcl   /*  681 */,
        0xc7caa854f5d7cdd3l   /*  682 */,    0x7cac32883d261d9cl   /*  683 */,
        0x7690c26423ba942cl   /*  684 */,    0x17e55524478042b8l   /*  685 */,
        0xe0be477656a2389fl   /*  686 */,    0x4d289b5e67ab2da0l   /*  687 */,
        0x44862b9c8fbbfd31l   /*  688 */,    0xb47cc8049d141365l   /*  689 */,
        0x822c1b362b91c793l   /*  690 */,    0x4eb14655fb13dfd8l   /*  691 */,
        0x1ecbba0714e2a97bl   /*  692 */,    0x6143459d5cde5f14l   /*  693 */,
        0x53a8fbf1d5f0ac89l   /*  694 */,    0x97ea04d81c5e5b00l   /*  695 */,
        0x622181a8d4fdb3f3l   /*  696 */,    0xe9bcd341572a1208l   /*  697 */,
        0x1411258643cce58al   /*  698 */,    0x9144c5fea4c6e0a4l   /*  699 */,
        0x0d33d06565cf620fl   /*  700 */,    0x54a48d489f219ca1l   /*  701 */,
        0xc43e5eac6d63c821l   /*  702 */,    0xa9728b3a72770dafl   /*  703 */,
        0xd7934e7b20df87efl   /*  704 */,    0xe35503b61a3e86e5l   /*  705 */,
        0xcae321fbc819d504l   /*  706 */,    0x129a50b3ac60bfa6l   /*  707 */,
        0xcd5e68ea7e9fb6c3l   /*  708 */,    0xb01c90199483b1c7l   /*  709 */,
        0x3de93cd5c295376cl   /*  710 */,    0xaed52edf2ab9ad13l   /*  711 */,
        0x2e60f512c0a07884l   /*  712 */,    0xbc3d86a3e36210c9l   /*  713 */,
        0x35269d9b163951cel   /*  714 */,    0x0c7d6e2ad0cdb5fal   /*  715 */,
        0x59e86297d87f5733l   /*  716 */,    0x298ef221898db0e7l   /*  717 */,
        0x55000029d1a5aa7el   /*  718 */,    0x8bc08ae1b5061b45l   /*  719 */,
        0xc2c31c2b6c92703al   /*  720 */,    0x94cc596baf25ef42l   /*  721 */,
        0x0a1d73db22540456l   /*  722 */,    0x04b6a0f9d9c4179al   /*  723 */,
        0xeffdafa2ae3d3c60l   /*  724 */,    0xf7c8075bb49496c4l   /*  725 */,
        0x9cc5c7141d1cd4e3l   /*  726 */,    0x78bd1638218e5534l   /*  727 */,
        0xb2f11568f850246al   /*  728 */,    0xedfabcfa9502bc29l   /*  729 */,
        0x796ce5f2da23051bl   /*  730 */,    0xaae128b0dc93537cl   /*  731 */,
        0x3a493da0ee4b29ael   /*  732 */,    0xb5df6b2c416895d7l   /*  733 */,
        0xfcabbd25122d7f37l   /*  734 */,    0x70810b58105dc4b1l   /*  735 */,
        0xe10fdd37f7882a90l   /*  736 */,    0x524dcab5518a3f5cl   /*  737 */,
        0x3c9e85878451255bl   /*  738 */,    0x4029828119bd34e2l   /*  739 */,
        0x74a05b6f5d3ceccbl   /*  740 */,    0xb610021542e13ecal   /*  741 */,
        0x0ff979d12f59e2acl   /*  742 */,    0x6037da27e4f9cc50l   /*  743 */,
        0x5e92975a0df1847dl   /*  744 */,    0xd66de190d3e623fel   /*  745 */,
        0x5032d6b87b568048l   /*  746 */,    0x9a36b7ce8235216el   /*  747 */,
        0x80272a7a24f64b4al   /*  748 */,    0x93efed8b8c6916f7l   /*  749 */,
        0x37ddbff44cce1555l   /*  750 */,    0x4b95db5d4b99bd25l   /*  751 */,
        0x92d3fda169812fc0l   /*  752 */,    0xfb1a4a9a90660bb6l   /*  753 */,
        0x730c196946a4b9b2l   /*  754 */,    0x81e289aa7f49da68l   /*  755 */,
        0x64669a0f83b1a05fl   /*  756 */,    0x27b3ff7d9644f48bl   /*  757 */,
        0xcc6b615c8db675b3l   /*  758 */,    0x674f20b9bcebbe95l   /*  759 */,
        0x6f31238275655982l   /*  760 */,    0x5ae488713e45cf05l   /*  761 */,
        0xbf619f9954c21157l   /*  762 */,    0xeabac46040a8eae9l   /*  763 */,
        0x454c6fe9f2c0c1cdl   /*  764 */,    0x419cf6496412691cl   /*  765 */,
        0xd3dc3bef265b0f70l   /*  766 */,    0x6d0e60f5c3578a9el   /*  767 */,
    };

    private static final long[] t4 = {
        0x5b0e608526323c55l   /*  768 */,    0x1a46c1a9fa1b59f5l   /*  769 */,
        0xa9e245a17c4c8ffal   /*  770 */,    0x65ca5159db2955d7l   /*  771 */,
        0x05db0a76ce35afc2l   /*  772 */,    0x81eac77ea9113d45l   /*  773 */,
        0x528ef88ab6ac0a0dl   /*  774 */,    0xa09ea253597be3ffl   /*  775 */,
        0x430ddfb3ac48cd56l   /*  776 */,    0xc4b3a67af45ce46fl   /*  777 */,
        0x4ececfd8fbe2d05el   /*  778 */,    0x3ef56f10b39935f0l   /*  779 */,
        0x0b22d6829cd619c6l   /*  780 */,    0x17fd460a74df2069l   /*  781 */,
        0x6cf8cc8e8510ed40l   /*  782 */,    0xd6c824bf3a6ecaa7l   /*  783 */,
        0x61243d581a817049l   /*  784 */,    0x048bacb6bbc163a2l   /*  785 */,
        0xd9a38ac27d44cc32l   /*  786 */,    0x7fddff5baaf410abl   /*  787 */,
        0xad6d495aa804824bl   /*  788 */,    0xe1a6a74f2d8c9f94l   /*  789 */,
        0xd4f7851235dee8e3l   /*  790 */,    0xfd4b7f886540d893l   /*  791 */,
        0x247c20042aa4bfdal   /*  792 */,    0x096ea1c517d1327cl   /*  793 */,
        0xd56966b4361a6685l   /*  794 */,    0x277da5c31221057dl   /*  795 */,
        0x94d59893a43acff7l   /*  796 */,    0x64f0c51ccdc02281l   /*  797 */,
        0x3d33bcc4ff6189dbl   /*  798 */,    0xe005cb184ce66af1l   /*  799 */,
        0xff5ccd1d1db99beal   /*  800 */,    0xb0b854a7fe42980fl   /*  801 */,
        0x7bd46a6a718d4b9fl   /*  802 */,    0xd10fa8cc22a5fd8cl   /*  803 */,
        0xd31484952be4bd31l   /*  804 */,    0xc7fa975fcb243847l   /*  805 */,
        0x4886ed1e5846c407l   /*  806 */,    0x28cddb791eb70b04l   /*  807 */,
        0xc2b00be2f573417fl   /*  808 */,    0x5c9590452180f877l   /*  809 */,
        0x7a6bddfff370eb00l   /*  810 */,    0xce509e38d6d9d6a4l   /*  811 */,
        0xebeb0f00647fa702l   /*  812 */,    0x1dcc06cf76606f06l   /*  813 */,
        0xe4d9f28ba286ff0al   /*  814 */,    0xd85a305dc918c262l   /*  815 */,
        0x475b1d8732225f54l   /*  816 */,    0x2d4fb51668ccb5fel   /*  817 */,
        0xa679b9d9d72bba20l   /*  818 */,    0x53841c0d912d43a5l   /*  819 */,
        0x3b7eaa48bf12a4e8l   /*  820 */,    0x781e0e47f22f1ddfl   /*  821 */,
        0xeff20ce60ab50973l   /*  822 */,    0x20d261d19dffb742l   /*  823 */,
        0x16a12b03062a2e39l   /*  824 */,    0x1960eb2239650495l   /*  825 */,
        0x251c16fed50eb8b8l   /*  826 */,    0x9ac0c330f826016el   /*  827 */,
        0xed152665953e7671l   /*  828 */,    0x02d63194a6369570l   /*  829 */,
        0x5074f08394b1c987l   /*  830 */,    0x70ba598c90b25ce1l   /*  831 */,
        0x794a15810b9742f6l   /*  832 */,    0x0d5925e9fcaf8c6cl   /*  833 */,
        0x3067716cd868744el   /*  834 */,    0x910ab077e8d7731bl   /*  835 */,
        0x6a61bbdb5ac42f61l   /*  836 */,    0x93513efbf0851567l   /*  837 */,
        0xf494724b9e83e9d5l   /*  838 */,    0xe887e1985c09648dl   /*  839 */,
        0x34b1d3c675370cfdl   /*  840 */,    0xdc35e433bc0d255dl   /*  841 */,
        0xd0aab84234131be0l   /*  842 */,    0x08042a50b48b7eafl   /*  843 */,
        0x9997c4ee44a3ab35l   /*  844 */,    0x829a7b49201799d0l   /*  845 */,
        0x263b8307b7c54441l   /*  846 */,    0x752f95f4fd6a6ca6l   /*  847 */,
        0x927217402c08c6e5l   /*  848 */,    0x2a8ab754a795d9eel   /*  849 */,
        0xa442f7552f72943dl   /*  850 */,    0x2c31334e19781208l   /*  851 */,
        0x4fa98d7ceaee6291l   /*  852 */,    0x55c3862f665db309l   /*  853 */,
        0xbd0610175d53b1f3l   /*  854 */,    0x46fe6cb840413f27l   /*  855 */,
        0x3fe03792df0cfa59l   /*  856 */,    0xcfe700372eb85e8fl   /*  857 */,
        0xa7be29e7adbce118l   /*  858 */,    0xe544ee5cde8431ddl   /*  859 */,
        0x8a781b1b41f1873el   /*  860 */,    0xa5c94c78a0d2f0e7l   /*  861 */,
        0x39412e2877b60728l   /*  862 */,    0xa1265ef3afc9a62cl   /*  863 */,
        0xbcc2770c6a2506c5l   /*  864 */,    0x3ab66dd5dce1ce12l   /*  865 */,
        0xe65499d04a675b37l   /*  866 */,    0x7d8f523481bfd216l   /*  867 */,
        0x0f6f64fcec15f389l   /*  868 */,    0x74efbe618b5b13c8l   /*  869 */,
        0xacdc82b714273e1dl   /*  870 */,    0xdd40bfe003199d17l   /*  871 */,
        0x37e99257e7e061f8l   /*  872 */,    0xfa52626904775aaal   /*  873 */,
        0x8bbbf63a463d56f9l   /*  874 */,    0xf0013f1543a26e64l   /*  875 */,
        0xa8307e9f879ec898l   /*  876 */,    0xcc4c27a4150177ccl   /*  877 */,
        0x1b432f2cca1d3348l   /*  878 */,    0xde1d1f8f9f6fa013l   /*  879 */,
        0x606602a047a7ddd6l   /*  880 */,    0xd237ab64cc1cb2c7l   /*  881 */,
        0x9b938e7225fcd1d3l   /*  882 */,    0xec4e03708e0ff476l   /*  883 */,
        0xfeb2fbda3d03c12dl   /*  884 */,    0xae0bced2ee43889al   /*  885 */,
        0x22cb8923ebfb4f43l   /*  886 */,    0x69360d013cf7396dl   /*  887 */,
        0x855e3602d2d4e022l   /*  888 */,    0x073805bad01f784cl   /*  889 */,
        0x33e17a133852f546l   /*  890 */,    0xdf4874058ac7b638l   /*  891 */,
        0xba92b29c678aa14al   /*  892 */,    0x0ce89fc76cfaadcdl   /*  893 */,
        0x5f9d4e0908339e34l   /*  894 */,    0xf1afe9291f5923b9l   /*  895 */,
        0x6e3480f60f4a265fl   /*  896 */,    0xeebf3a2ab29b841cl   /*  897 */,
        0xe21938a88f91b4adl   /*  898 */,    0x57dfeff845c6d3c3l   /*  899 */,
        0x2f006b0bf62caaf2l   /*  900 */,    0x62f479ef6f75ee78l   /*  901 */,
        0x11a55ad41c8916a9l   /*  902 */,    0xf229d29084fed453l   /*  903 */,
        0x42f1c27b16b000e6l   /*  904 */,    0x2b1f76749823c074l   /*  905 */,
        0x4b76eca3c2745360l   /*  906 */,    0x8c98f463b91691bdl   /*  907 */,
        0x14bcc93cf1ade66al   /*  908 */,    0x8885213e6d458397l   /*  909 */,
        0x8e177df0274d4711l   /*  910 */,    0xb49b73b5503f2951l   /*  911 */,
        0x10168168c3f96b6bl   /*  912 */,    0x0e3d963b63cab0ael   /*  913 */,
        0x8dfc4b5655a1db14l   /*  914 */,    0xf789f1356e14de5cl   /*  915 */,
        0x683e68af4e51dac1l   /*  916 */,    0xc9a84f9d8d4b0fd9l   /*  917 */,
        0x3691e03f52a0f9d1l   /*  918 */,    0x5ed86e46e1878e80l   /*  919 */,
        0x3c711a0e99d07150l   /*  920 */,    0x5a0865b20c4e9310l   /*  921 */,
        0x56fbfc1fe4f0682el   /*  922 */,    0xea8d5de3105edf9bl   /*  923 */,
        0x71abfdb12379187al   /*  924 */,    0x2eb99de1bee77b9cl   /*  925 */,
        0x21ecc0ea33cf4523l   /*  926 */,    0x59a4d7521805c7a1l   /*  927 */,
        0x3896f5eb56ae7c72l   /*  928 */,    0xaa638f3db18f75dcl   /*  929 */,
        0x9f39358dabe9808el   /*  930 */,    0xb7defa91c00b72acl   /*  931 */,
        0x6b5541fd62492d92l   /*  932 */,    0x6dc6dee8f92e4d5bl   /*  933 */,
        0x353f57abc4beea7el   /*  934 */,    0x735769d6da5690cel   /*  935 */,
        0x0a234aa642391484l   /*  936 */,    0xf6f9508028f80d9dl   /*  937 */,
        0xb8e319a27ab3f215l   /*  938 */,    0x31ad9c1151341a4dl   /*  939 */,
        0x773c22a57bef5805l   /*  940 */,    0x45c7561a07968633l   /*  941 */,
        0xf913da9e249dbe36l   /*  942 */,    0xda652d9b78a64c68l   /*  943 */,
        0x4c27a97f3bc334efl   /*  944 */,    0x76621220e66b17f4l   /*  945 */,
        0x967743899acd7d0bl   /*  946 */,    0xf3ee5bcae0ed6782l   /*  947 */,
        0x409f753600c879fcl   /*  948 */,    0x06d09a39b5926db6l   /*  949 */,
        0x6f83aeb0317ac588l   /*  950 */,    0x01e6ca4a86381f21l   /*  951 */,
        0x66ff3462d19f3025l   /*  952 */,    0x72207c24ddfd3bfbl   /*  953 */,
        0x4af6b6d3e2ece2ebl   /*  954 */,    0x9c994dbec7ea08del   /*  955 */,
        0x49ace597b09a8bc4l   /*  956 */,    0xb38c4766cf0797bal   /*  957 */,
        0x131b9373c57c2a75l   /*  958 */,    0xb1822cce61931e58l   /*  959 */,
        0x9d7555b909ba1c0cl   /*  960 */,    0x127fafdd937d11d2l   /*  961 */,
        0x29da3badc66d92e4l   /*  962 */,    0xa2c1d57154c2ecbcl   /*  963 */,
        0x58c5134d82f6fe24l   /*  964 */,    0x1c3ae3515b62274fl   /*  965 */,
        0xe907c82e01cb8126l   /*  966 */,    0xf8ed091913e37fcbl   /*  967 */,
        0x3249d8f9c80046c9l   /*  968 */,    0x80cf9bede388fb63l   /*  969 */,
        0x1881539a116cf19el   /*  970 */,    0x5103f3f76bd52457l   /*  971 */,
        0x15b7e6f5ae47f7a8l   /*  972 */,    0xdbd7c6ded47e9ccfl   /*  973 */,
        0x44e55c410228bb1al   /*  974 */,    0xb647d4255edb4e99l   /*  975 */,
        0x5d11882bb8aafc30l   /*  976 */,    0xf5098bbb29d3212al   /*  977 */,
        0x8fb5ea14e90296b3l   /*  978 */,    0x677b942157dd025al   /*  979 */,
        0xfb58e7c0a390acb5l   /*  980 */,    0x89d3674c83bd4a01l   /*  981 */,
        0x9e2da4df4bf3b93bl   /*  982 */,    0xfcc41e328cab4829l   /*  983 */,
        0x03f38c96ba582c52l   /*  984 */,    0xcad1bdbd7fd85db2l   /*  985 */,
        0xbbb442c16082ae83l   /*  986 */,    0xb95fe86ba5da9ab0l   /*  987 */,
        0xb22e04673771a93fl   /*  988 */,    0x845358c9493152d8l   /*  989 */,
        0xbe2a488697b4541el   /*  990 */,    0x95a2dc2dd38e6966l   /*  991 */,
        0xc02c11ac923c852bl   /*  992 */,    0x2388b1990df2a87bl   /*  993 */,
        0x7c8008fa1b4f37bel   /*  994 */,    0x1f70d0c84d54e503l   /*  995 */,
        0x5490adec7ece57d4l   /*  996 */,    0x002b3c27d9063a3al   /*  997 */,
        0x7eaea3848030a2bfl   /*  998 */,    0xc602326ded2003c0l   /*  999 */,
        0x83a7287d69a94086l   /* 1000 */,    0xc57a5fcb30f57a8al   /* 1001 */,
        0xb56844e479ebe779l   /* 1002 */,    0xa373b40f05dcbce9l   /* 1003 */,
        0xd71a786e88570ee2l   /* 1004 */,    0x879cbacdbde8f6a0l   /* 1005 */,
        0x976ad1bcc164a32fl   /* 1006 */,    0xab21e25e9666d78bl   /* 1007 */,
        0x901063aae5e5c33cl   /* 1008 */,    0x9818b34448698d90l   /* 1009 */,
        0xe36487ae3e1e8abbl   /* 1010 */,    0xafbdf931893bdcb4l   /* 1011 */,
        0x6345a0dc5fbbd519l   /* 1012 */,    0x8628fe269b9465cal   /* 1013 */,
        0x1e5d01603f9c51ecl   /* 1014 */,    0x4de44006a15049b7l   /* 1015 */,
        0xbf6c70e5f776cbb1l   /* 1016 */,    0x411218f2ef552bedl   /* 1017 */,
        0xcb0c0708705a36a3l   /* 1018 */,    0xe74d14754f986044l   /* 1019 */,
        0xcd56d9430ea8280el   /* 1020 */,    0xc12591d7535f5065l   /* 1021 */,
        0xc83223f1720aef96l   /* 1022 */,    0xc3a0396f7363a51fl   /* 1023 */
    };

    private static final int    digest_length = 24;

    //
    // registers
    //
    private long    a, b, c;
    private long    bytecount;

    //
    // buffers
    //
    private byte[]  buf = new byte[8];
    private int     boff = 0;

    private long[]  x = new long[8];
    private int     xoff = 0;

    /**
     * standard constructor
     */
    public tigerdigest()
    {
        reset();
    }

    /**
     * copy constructor.  this will copy the state of the provided
     * message digest.
     */
    public tigerdigest(tigerdigest t)
    {
        this.reset(t);
    }

    public string getalgorithmname()
    {
        return "tiger";
    }

    public int getdigestsize()
    {
        return digest_length;
    }

    private void processword(
        byte[]  b,
        int     off)
    {
        x[xoff++] = ((long)(b[off + 7] & 0xff) << 56)
             | ((long)(b[off + 6] & 0xff) << 48)
             | ((long)(b[off + 5] & 0xff) << 40)
             | ((long)(b[off + 4] & 0xff) << 32)
             | ((long)(b[off + 3] & 0xff) << 24)
             | ((long)(b[off + 2] & 0xff) << 16)
             | ((long)(b[off + 1] & 0xff) << 8)
             | ((b[off + 0] & 0xff));

        if (xoff == x.length)
        {
            processblock();
        }

        boff = 0;
    }

    public void update(
        byte in)
    {
        buf[boff++] = in;

        if (boff == buf.length)
        {
            processword(buf, 0);
        }

        bytecount++;
    }

    public void update(
        byte[]  in,
        int     inoff,
        int     len)
    {
        //
        // fill the current word
        //
        while ((boff != 0) && (len > 0))
        {
            update(in[inoff]);

            inoff++;
            len--;
        }

        //
        // process whole words.
        //
        while (len > 8)
        {
            processword(in, inoff);

            inoff += 8;
            len -= 8;
            bytecount += 8;
        }

        //
        // load in the remainder.
        //
        while (len > 0)
        {
            update(in[inoff]);

            inoff++;
            len--;
        }
    }

    private void roundabc(
        long    x,
        long    mul)
    {
         c ^= x ;
         a -= t1[(int)c & 0xff] ^ t2[(int)(c >> 16) & 0xff]
                ^ t3[(int)(c >> 32) & 0xff] ^ t4[(int)(c >> 48) & 0xff];
         b += t4[(int)(c >> 8) & 0xff] ^ t3[(int)(c >> 24) & 0xff]
                ^ t2[(int)(c >> 40) & 0xff] ^ t1[(int)(c >> 56) & 0xff];
         b *= mul;
    }

    private void roundbca(
        long    x,
        long    mul)
    {
         a ^= x ;
         b -= t1[(int)a & 0xff] ^ t2[(int)(a >> 16) & 0xff]
                ^ t3[(int)(a >> 32) & 0xff] ^ t4[(int)(a >> 48) & 0xff];
         c += t4[(int)(a >> 8) & 0xff] ^ t3[(int)(a >> 24) & 0xff]
                ^ t2[(int)(a >> 40) & 0xff] ^ t1[(int)(a >> 56) & 0xff];
         c *= mul;
    }

    private void roundcab(
        long    x,
        long    mul)
    {
         b ^= x ;
         c -= t1[(int)b & 0xff] ^ t2[(int)(b >> 16) & 0xff]
                ^ t3[(int)(b >> 32) & 0xff] ^ t4[(int)(b >> 48) & 0xff];
         a += t4[(int)(b >> 8) & 0xff] ^ t3[(int)(b >> 24) & 0xff]
                ^ t2[(int)(b >> 40) & 0xff] ^ t1[(int)(b >> 56) & 0xff];
         a *= mul;
    }

    private void keyschedule()
    {
        x[0] -= x[7] ^ 0xa5a5a5a5a5a5a5a5l; 
        x[1] ^= x[0]; 
        x[2] += x[1]; 
        x[3] -= x[2] ^ ((~x[1]) << 19); 
        x[4] ^= x[3]; 
        x[5] += x[4]; 
        x[6] -= x[5] ^ ((~x[4]) >>> 23); 
        x[7] ^= x[6]; 
        x[0] += x[7]; 
        x[1] -= x[0] ^ ((~x[7]) << 19); 
        x[2] ^= x[1]; 
        x[3] += x[2]; 
        x[4] -= x[3] ^ ((~x[2]) >>> 23); 
        x[5] ^= x[4]; 
        x[6] += x[5]; 
        x[7] -= x[6] ^ 0x0123456789abcdefl;
    }

    private void processblock()
    {
        //
        // save abc
        //
        long aa = a;
        long bb = b;
        long cc = c;

        //
        // rounds and schedule
        //
        roundabc(x[0], 5);
        roundbca(x[1], 5);
        roundcab(x[2], 5);
        roundabc(x[3], 5);
        roundbca(x[4], 5);
        roundcab(x[5], 5);
        roundabc(x[6], 5);
        roundbca(x[7], 5);

        keyschedule();

        roundcab(x[0], 7);
        roundabc(x[1], 7);
        roundbca(x[2], 7);
        roundcab(x[3], 7);
        roundabc(x[4], 7);
        roundbca(x[5], 7);
        roundcab(x[6], 7);
        roundabc(x[7], 7);

        keyschedule();

        roundbca(x[0], 9);
        roundcab(x[1], 9);
        roundabc(x[2], 9);
        roundbca(x[3], 9);
        roundcab(x[4], 9);
        roundabc(x[5], 9);
        roundbca(x[6], 9);
        roundcab(x[7], 9);

        //
        // feed forward
        //
        a ^= aa;
        b -= bb;
        c += cc;

        //
        // clear the x buffer
        //
        xoff = 0;
        for (int i = 0; i != x.length; i++)
        {
            x[i] = 0;
        }
    }

    public void unpackword(
        long    r,
        byte[]  out,
        int     outoff)
    {
        out[outoff + 7]     = (byte)(r >> 56);
        out[outoff + 6] = (byte)(r >> 48);
        out[outoff + 5] = (byte)(r >> 40);
        out[outoff + 4] = (byte)(r >> 32);
        out[outoff + 3] = (byte)(r >> 24);
        out[outoff + 2] = (byte)(r >> 16);
        out[outoff + 1] = (byte)(r >> 8);
        out[outoff] = (byte)r;
    }
        
    private void processlength(
        long    bitlength)
    {
        x[7] = bitlength;
    }

    private void finish()
    {
        long    bitlength = (bytecount << 3);

        update((byte)0x01);

        while (boff != 0)
        {
            update((byte)0);
        }

        processlength(bitlength);

        processblock();
    }

    public int dofinal(
        byte[]  out,
        int     outoff)
    {
        finish();

        unpackword(a, out, outoff);
        unpackword(b, out, outoff + 8);
        unpackword(c, out, outoff + 16);

        reset();

        return digest_length;
    }

    /**
     * reset the chaining variables
     */
    public void reset()
    {
        a = 0x0123456789abcdefl;
        b = 0xfedcba9876543210l;
        c = 0xf096a5b4c3b2e187l;

        xoff = 0;
        for (int i = 0; i != x.length; i++)
        {
            x[i] = 0;
        }

        boff = 0;
        for (int i = 0; i != buf.length; i++)
        {
            buf[i] = 0;
        }

        bytecount = 0;
    }

    public int getbytelength()
    {
        return byte_length;
    }

    public memoable copy()
    {
        return new tigerdigest(this);
    }

    public void reset(memoable other)
    {
        tigerdigest t = (tigerdigest)other;

        a = t.a;
        b = t.b;
        c = t.c;

        system.arraycopy(t.x, 0, x, 0, t.x.length);
        xoff = t.xoff;

        system.arraycopy(t.buf, 0, buf, 0, t.buf.length);
        boff = t.boff;

        bytecount = t.bytecount;
    }
}
