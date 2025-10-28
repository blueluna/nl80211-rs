# nl80211 built tools

A helper crate for generating code from JSON definition files.

These JSON definition files can be generated with the `specgen` tool found as an example in this crate.

## Specification generator

```shell
specgen -i <intput> -o <output> -n <name> -t <type>
```

Generates a specification file from a (nl80211) kernel header.

 - `<intput>`, Path to the `nl80211.h` kernel header
 - `<output>`, Path to the description file to write
 - `<name>`, Name of the enum or attribute to describe.
 - `<type>`, Either "enum" or "attribute" to generate an attribute or enumeration description.

```shell
specgen -i /usr/include/linux/nl80211.h -n nl80211_attrs -t attribute -o nl80211_attributes.json
```
