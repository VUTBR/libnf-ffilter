# Ffilter documentation

## Authors
Imrich Štoffa, Tomáš Podermansky, Lukás Huták

## Purpose
This filter was created for unification of network metadate filtering languages in tools ipfixcol and fdistdump. The nfdump filter was choosed as basis and was generalised to support more identifiers.

## Dependencies
Filter uses *bison* and *flex* to scan and parse input language, so these are essential. Nothing else so far. 

## Syntax:

Filtering expression looks like this.
```
<expression> : <identifier> <operator> <value>
```
Where
```
<identifier>
```
is field name, validated by lookup function,

```
<operator>
``` 
is one of notations in table,
Notation | Semantics | Info
--- | --- | ---
 | eq by default | Can by changed by modifying opitions in lvalue returned from lookup func
eq, ==, = | equality | strcmp() output for strings, 
gt, > | greater than | Honours singedness
lt, < | little that | Honours singedness
& | like/bit-and | Check for presence of bits, with strings use substr() for evaluation

```
<value>
``` 
is maximally one space separated sequence of digits or letters.

Expressions might be connected with operators: &&, and, ||, or, !, not. Precedence can be
changed by parenthesis.

# Design
![Filter Module Scheme](doc/filter_data_model.png)

Filter module (FM) requires user to implement interface functions, it might provide some default implementation for demonstration in future. _lookup\_func_ priovides valid field names and associates them with FM internal data types. Each field name has assigned external identification, a number which will identify it later during evaluation of filter tree. Theese external ids must be known to _data\_func_ function which filter uses to retrieve data from record. Lookup callback is only called during compilation of filter expression, whereas data callback is called by _ff\_eval_ on each leaf of filter tree.

Basically what that image is trying to express is that filter module must be provided interface implementation to function. Compilation uses these functions and generates filter tree. This tree is supossed to be evaluated against data fields provided by data callback from data records.

There are some ugly hacks in scanner and parser grammars to support separated field identifiers and fields with default assigned values - literal constants, which will be fixed.
