radar nodestore
-----------------

to understand a shamap first you must know about the nodestore.

```java
/**

 * this is a toy implementation for illustrative purposes.
 */
public class nodestore {
    /**
    * in ripple, all data is stored in a simple binary key/value database.
    * the keys are 256 bit binary strings and the values are binary strings of
    * arbitrary length.
    */
    public static interface keyvaluebackend {
        void   put(hash256 key, byte[] content);
        byte[] get(hash256 key);
    }

    keyvaluebackend backend;
    public nodestore(keyvaluebackend backend) {
        this.backend = backend;
    }
    /**
     * all data stored is keyed by the hash of it's contents.
     * ripple uses the first 256 bits of a sha512 as it's 33 percent
     * faster than using sha256.
     *
     * @return `key` used to store the content
     */
    private hash256 storecontent(byte[] content) {
        hash256.halfsha512 hasher = new hash256.halfsha512();
        hasher.update(content);
        hash256 key = hasher.finish();
        storehashkeyedcontent(key, content);
        return key;
    }

    /**
     * @param hash as ripple uses the `hash` of the contents as the
     *             nodestore key, `hash` is pervasively used in lieu of
     *             the term `key`.
     */
    private void storehashkeyedcontent(hash256 hash, byte[] content) {
        // note: the real nodestore actually prepends some metadata, which doesn't
        // contribute to the hash.
        backend.put(hash, content); // metadata + content
    }

    /**
     * the complement to `set` api, which together form a simple public interface.
     */
    public byte[] get(hash256 hash) {
        return backend.get(hash);

    }
    /**
     * the complement to `get` api, which together form a simple public interface.
     */
    public hash256 set(byte[] content) {
        return storecontent(content);
    }
}
```

see also:
* [serialized types](../../readme.md)
* [binaryformats.txt (historical)](https://github.com/ripple/rippled/blob/07df5f1f81b0ee1ab641d134ba8e940a90f5297e/binaryformats.txt#l2-l6)

excerpt from binaryformats.txt (historical): 

  <blockquote>
  all signed or hashed objects must have well-defined binary formats at the
  byte level. these formats do not have to be the same as the network wire
  formats or the forms used for efficient storage or human display. however,
  it must always be possible to precisely re-create, byte for byte, any signed
  or hashed object. otherwise, the signatures or hashes cannot be validated.
  </blockquote>

note that currently (2/feb/2014) the nodestore stores it in the hashing form.

what is a shamap?
-----------------

a shamap is a special type of tree, used as a way to index values stored in a
`nodestore`

recall that values in the nodestore are keyed by the hash of their contents.

but what about identities that change over time? how can you retrieve a certain
version of something? what could be used as an enduring identifier? the value
must have some component[s] that are static over time. these are fed into a
hashing function to create a 256 bit identifier.

but how is this used? you can only query values by `hash` in the nodestore. the
hash, as a function of a value would obviously change along with it.

the identifier is used as an `index` into a shamap tree, which in ripple, is
representative of a point in time. in fact a shamap can be hashed
deterministically, thus a point in time can be identified by a `hash`. where is
a shamap actually stored? in the nodestore, of course.

but the nodestore only stores binary content you protest! but the shamap has a
binary representation! so what are the `contents` of a shamap, to be hashed to
be stored in the nodestore?

glad you asked. a tree, has a root, and many children, either more branches, or
terminal leaves. the root, and any of its children that have children
themselves, are classed as `inner nodes`.

in a shamap these `inner nodes` each have 16 `slots` for children. the binary
representation of these is simply 16 `hash`es, used to retrieve child nodes from
the nodestore.

an example of an inner node's `contents`

  empty slots are represented as 32 0 bytes

  ```
  022cc592f5d4abc3a63da2a036cddc0825b30717c78ef287bef200056133fda2
  0000000000000000000000000000000000000000000000000000000000000000
  bee626551799ddfe65bd2d9a0f0ea24d72c93cfd8e083176718d2b079ec60214
  e1b34f1d9209cb668a50ccee71c8109d140a6d715d923aee98e6d53015d8b66b
  4c27a856094cfde37cd2a0ea93dadb595b10cfec55f816c987a6ac48d13af5c0
  2f770714a9ef92792f44aa1537c18f68afe3fff157fb9088ffe2bda695c19b71
  c915ca982310cf41cf1266aa43c3b31acbf4304d05adb54a352d942c890763a3
  f29fad442ce204513bea555a4192e324407444d946449cea510c37a9bb982134
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  44b3be10744ea2da010d530c6ae64e3c3984da7701ee79a66ea429ec11b87d1d
  0c7be8569e9f08baddeb91ebe79e5b98bbf245b067b7b83b4a95430cfec9f7e8
  bb38ea169db6a020ea820bd1242ddb6250b397a26015507ba3c7f3c041ea683c
  0000000000000000000000000000000000000000000000000000000000000000
  15b98934d22b5cb7233c42ce8dc8dd0d2328ab91cc574332c45d7160bd31d4ad
  1894e389ae4a63ba99c2d0546a58a976ecdab14c09b98f532999b464696e29e5
  ```

what about those `index` thingies again? remember, the `index` can't be used to
query something directly in the nodestore.

first you need a known point in time, which we learned could be defined by a
`hash` of a shamap.

* shamap hash: e4984329ffd3d06c882706c190503412b0af49a37499be2df82251f94d5cc3e6
* value index: df68ee71ee9141e24b87e630976c1f9071f74ad073bd03578083fdd9098b4bd9

imagine we have those above. first we query the nodestore with `e49843...`

what do we expect back? a shamap hash is the hash of the binary representation
of the root node (which is an `inner node`) of the tree, so we'd expect
something in the form shown earlier, with 16 256 bit hashes.

from the nodestore we retrieve:

  ```
  40494e00
  da0e8e7247bd8f35d53d3cb9308a1f63f2a1ffc9c6f92f5bc4f8f2ae227ce5b3
  685cdda83db325fff2cb72a3d70bd63e65f77b2811e95a18a49906439d360424
  6450a66258d9cd3fd51d49e4f636f1fa7fa5d7cb8594605da4539377cfd1366c
  897bfbe62ef1141396d583c9a22408d9608b02f0044382ca717a1670eb09ffd8
  da482a1708eafbf2e3ff455215692db37dfcea866badc111baf2b5b488af326a
  339535d1fc79bfc345a93f4043333eede77f79f9272944a5bc65ffc287c009e7
  7dd55b28d92ca53a80d04be1ee37723e1be5c739882281167addeb0dfdb82fa0
  7b1e3dc2d03df0d0f3048bfd159604d92abca894a18d74ff9c1aeff11b7129fb
  c37f30564948140da6c1f247636747eef749e6b5f4f52a9bfb9f25066b322f91
  a86de64af331fd05f783e2702c748fe21f46c121ca6a4ba164033a8c9ae9a332
  36744569307984372139d3a25b43eb2abb1485e7bfd87eb9e46f40ed56447c45
  5ca21c8d6d437c978a63d243d67798977de1e5d09c6cab2e897db6a4ea998589
  db3dc38fb1ea94da778beb6a60414dfc96e83c2c8e49283bb139e963d1bc5e98
  7c0b1c90cd3ae3446f65a1f59b36e5c990a7386c1d513e224a59ba404b6ed58c
  5c8bd6b57668fbbae9bd683f2184eb494b9657a711c9b86d67f14fa3d84023b9
  838777adaf945a4cb481644b6d0923c807375cf3d7b3ded87268d144d7c09768
  ```

we see the hashes for 16 nodes clear as day, but what is this `40494e00`
prefixed to the front? converted to `ascii` letters the hex `40494e00` is 
`min\x00`, meaning sham)ap i)nner n)ode.

the prefix `namespaces` the content, so different classes of objects which
would otherwise have the same binary representation, will have a different
`hash`. these `hash prefixes` serve another useful purpose, as we'll see later.
(similarly, there are namespacing prefixes for an `index` (created by
 feeding static components of an identity into a hashing function))

is our value `index` hash amongst those enumerated? no !!! so what do we do with
it? an index, usually means an ordinal, defining a place in an array. the
`index` is actually an index into 64 arrays. each nibble in the `index` is an
index into the 16 slots in each inner node.

consider again the value `index`:

  `df68ee71ee9141e24b87e630976c1f9071f74ad073bd03578083fdd9098b4bd9`

to use the `index` we take the first nibble, `d` (yes, we go left to right)

the letter `d` in hex has the ordinal value 13, so we take the 14th branch (0
based indexing)

  (if this is unclear, see `annoyingly verbose` ascii art @ bottom of section)

we select the 14th hash

  `7c0b1c90cd3ae3446f65a1f59b36e5c990a7386c1d513e224a59ba404b6ed58c`

from the nodestore we retrieve:

  ```
  40494e00
  25ccd7be2cb8bc77c832bdb55659e4c5cf9fd9c062164bee6eb8a92be93f19fe
  98998c886894a87a4d4e0553d629804086526b8aa4d0856861060843acaf38a8
  bf2b532a44cc3373283ab9ea499cf7c313488dcf068310868c4f49847041e3ee
  a2c09e311166ff62d669319e3554e8ba2ccdc53f0745cf44cfefb266f0e50619
  40d4babaebf0501b86b45db8d857eb06aefd359dd3387d53e4aee8bdffc65673
  5805bef8086f70e34534796c38fb62ffc977298ac3f25a6c13d82200292c7ad5
  bf9cc8b96324f619ffb3ae82cf898c58c4c191ecb902f87bb69634a5e8a25ab6
  537d11d98003e92f5ab45f96e20f2df89f4766f632a6b2bd911cdef7f94ff556
  df2a4b52b0dbbdfe5be97f116414bc31c2d7aacba2f1cf801977c523399d950e
  6f09a1de35b7d9931f6ec38bee5c75f0d0057b15ab5d5171f9441671eff4f5aa
  b49303b5d6eb092021c4c0f3e4a1943e49a7cd661e8c77bd99faa72335b03d47
  08813d9c2d3103bb3d8234f38f25a1834f5d6db1118f578c9811fd4217c37850
  c425aaab4b35502b9f14d3f265955be72ca741aa19876a315d999f7f0ffd1324
  15cad3899e675402f19546016570252778a61d900d9e54d5a217a348db245557
  34257698b5a753495a416d0ec8e1b45e438563d12af66210b8f40a3cd69e84f2
  272d03dc4d1a559ff23dada65fffb652e7a727f5d857bec83c029bc662f79034
  ```

there's that 'min\x00` hash prefix again.

in fact, this prefix is how we can deterministically say that this is an
`inner node` and that we can interpret the following bytes as 16 more
`hash`es.

we have descended deeper into the tree, but it seems we need to go deeper. we
are currently at a depth of 2, so to go deeper we need the 2nd nibble.

value index:
  ```
  df68ee71ee9141e24b87e630976c1f9071f74ad073bd03578083fdd9098b4bd9`
   |
    \
     2nd nibble
  ```

the letter `f` in hex has the ordinal value 15, so we take the 16th branch (0
based indexing)

we select the 16th hash:

  `272d03dc4d1a559ff23dada65fffb652e7a727f5d857bec83c029bc662f79034`

from the nodestore we retrieve:

  ```
  4d4c4e00
  201c00000000f8e311006f563596ce72c902bafaab56cc486acaf9b
  4afc67cf7cadbb81a4aa9cbdc8c5cb1aae824000195f93400000000
  0000000e501062a3338caf2e1bee510fc33de1863c56948e962cce1
  73ca55c14be8a20d7f00064400000170a53ac2065d5460561ec9de0
  00000000000000000000000000494c53000000000092d705968936c
  419ce614bf264b5eeb1cea47ff4811439408a69f0895e62149cfcc0
  06fb89fa7
  df68ee71ee9141e24b87e630976c1f9071f74ad073bd03578083fdd9098b4bd9
  ```

well, here's something new. the `hash prefix` is different. this time the
hex decodes as `mln\x00`, meaning sham)ap l)eaf n)ode.

and what's that at the end? is that our index? it is!!

why does it need to be stored? we have only used `df` to traverse to this
node. without storing the `index` identifier in the leaf node contents,
there would be no way to be certain that this leaf held the item you wanted.
more importantly, it acts as further name-spacing, to prevent collisions. 
(technically, you could synthesize the index, by parsing the contents of
the object and recreating it)

takeaways
---------

* a `hash` keys the nodestore
* an `index` is a path to an item in a shamap
* for communication purposes
  - always use `hash` when referring to a key for the nodestore
  - always use `index` when referring to a key for a shamap

links
-----

* [shamapinnernodeanalyis](../../../../../../../../../ripple-examples/ripple-cli/src/main/java/com/ripple/cli/shamapanalysis/shamapinnernodeanalysis.java)
* [rippled hash prefix declarations](https://github.com/ripple/ripple-lib-java/blob/master/ripple-core/src/main/java/com/ripple/core/coretypes/hash/prefixes/hashprefix.java)

annoyingly verbose ascii art
----------------------------

```
  df68ee71ee9141e24b87e630976c1f9071f74ad073bd03578083fdd9098b4bd9
  || \_____
  \ \____  \
   \___  \  \
       d  f  6  8   e  e  7  1   e  e  9  1   4  1  e  2   4  b  8  7   e  6
^ <----                 nibble (depth of inner node)                       ---->
|     01 02 03 04  05 06 07 08  09 10 11 12  13 14 15 16  17 18 19 20  21 22 ...

s      !  !  !  !   !  !  !  !   !  !  !  !   !  !  !  !   !  !  !  !   !  !
l
o  00  |  |  |  |   |  |  |  |   |  |  |  |   |  |  |  |   |  |  |  |   |  |
t  01  |  |  |  |   |  |  |  1   |  |  |  1   |  1  |  |   |  |  |  |   |  |
   02  |  |  |  |   |  |  |  |   |  |  |  |   |  |  |  2   |  |  |  |   |  |
i  03  |  |  |  |   |  |  |  |   |  |  |  |   |  |  |  |   |  |  |  |   |  |
n
   04  |  |  |  |   |  |  |  |   |  |  |  |   4  |  |  |   4  |  |  |   |  |
i  05  |  |  |  |   |  |  |  |   |  |  |  |   |  |  |  |   |  |  |  |   |  |
n  06  |  |  6  |   |  |  |  |   |  |  |  |   |  |  |  |   |  |  |  |   |  6
n  07  |  |  |  |   |  |  7  |   |  |  |  |   |  |  |  |   |  |  |  7   |  |
e
r  08  |  |  |  8   |  |  |  |   |  |  |  |   |  |  |  |   |  |  8  |   |  |
   09  |  |  |  |   |  |  |  |   |  |  9  |   |  |  |  |   |  |  |  |   |  |
n  10  |  |  |  |   |  |  |  |   |  |  |  |   |  |  |  |   |  |  |  |   |  |
o  11  |  |  |  |   |  |  |  |   |  |  |  |   |  |  |  |   |  b  |  |   |  |
d
e  12  |  |  |  |   |  |  |  |   |  |  |  |   |  |  |  |   |  |  |  |   |  |
   13 [d] |  |  |   |  |  |  |   |  |  |  |   |  |  |  |   |  |  |  |   |  |
|  14  |  |  |  |   e  e  |  |   e  e  |  |   |  |  *  |   |  |  |  |   e  |
v  15  |  f  |  |   |  |  |  |   |  |  |  |   |  |  |  |   |  |  |  |   |  |
```
