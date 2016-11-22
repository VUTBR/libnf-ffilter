# Ffilter documentation

## Authors
Imrich Štoffa, Tomáš Podermansky, Lukás Huták

## Purpose
This filter was created for unification of network metadate filtering languages in tools ipfixcol and fdistdump. The nfdump filter was choosed as basis and was generalised to support more identifiers.

## Dependencies
Filter uses *bison* and *flex* to scan and parse input language, so these are essential. Nothing else so far. 

## Syntax:

Filtering expression looks like this:

```
<expression> : <expression> <operator> <expression>
             : <not_operator> <expression>
             : ( <expression> )
             : <identifier> <comparator> <value>
             : <identifier> in [ <value> ... ]
```

Where
```
<operator>
``` 
one of notations in table

Notation | Semantics | Info
--- | --- | ---
 AND, && | logical and | Both expressions must be true, has priority over OR
OR, \|\| | logical or | At least one must be true, 

```
<not_operator>
``` 
stands for unary logical nagation of expression, has priority over logic operators

```
<identifier>
```
field name, validated by lookup function

```
<omparator>
``` 
is one of notations in table

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
is sequence of digits or letters, regex: "([0-9] | [A-Za-z:/\.\-])+", value can be composed of two such strings

# Design
![Filter Module Scheme](doc/filter_data_model.png)

Filter module (FM) requires user to implement interface functions, it might provide some default implementation for demonstration in future. _ff\_lookup\_func_ priovides valid field names and associates them with FM internal data types. Each field name has assigned external identification, a number which will identify it later during evaluation of filter tree. Theese external ids must be known to _ff\_data\_func_ function which filter uses to retrieve data from record. Lookup callback is only called during compilation of filter expression, whereas data callback is called by _ff\_eval_ on each leaf of filter tree.

Basically what that image is trying to express is that filter module must be provided interface implementation to function. Compilation uses these functions and generates filter tree. This tree is supossed to be evaluated against data fields provided by data callback from data records.


