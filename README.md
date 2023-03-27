# Rust Low Hanging Fruiter
Simple script to detect potential vulnerabilities in a code review. 
It make use of Python regular expressions to find incidences and the knowledge base is just a text file with 
vulnerability definitions. At the moment, it only works for **Rust**, but it will be modified to work with other languages. 


## Usage
Just modify **vuln_definition.conf** and **cargo_checks.conf**, on their respectives language folder (_./Rust/_) 
as you wish and execute this script.
```
$ python3 lhf.py -h                                                                          
usage: lhf.py [-h] -p PATH [-v VULN_CONF] [-l LANGUAGE] [-ew EXCLUDE_WORDS] [-ep EXCLUDE_PATHS] [-o OFILE] [-s]

Simple and scalable script to find low hanging fruites in code reviews

optional arguments:
  -h, --help            show this help message and exit
  -p PATH, --path PATH  Absolute path to search in
  -v VULN_CONF, --vuln_conf VULN_CONF
                        Vulnerability descriptions file
  -l LANGUAGE, --language LANGUAGE
                        Language to parse: rust or solidity (Default: rust)
  -ew EXCLUDE_WORDS, --exclude-words EXCLUDE_WORDS
                        List of words, comma separated, to exclude from results if found
  -ep EXCLUDE_PATHS, --exclude-paths EXCLUDE_PATHS
                        List of paths, comma separated, to exclude from results if found
  -o OFILE, --ofile OFILE
                        Regular output file
  -s, --simplified      Simplified greppeable output

```

## Limitations
This tool does not review:
- Syntax integrity
- Semantic meaning
- UTF-8 encodings
- Advanced borrowed or propagated variables
- Recursion
- Memory Problems and Leaks
- Logic Errors

## Note

This is not a complete release nor intended to be a stable development. **This is just a script for helping in code review.**<br>
It could be (*and it will be*) false positives 
and errors. Please, do not completely trust in this tool and manually review the code.

For any doubts or modifications just send a message to **//pablo**

# APPENDIX: Vulnerability definition
Vulnerability definition in csv format. This file must be stored over a respective language folder. For example, for rust definitions, 
must be included in ./Rust/ folder, for solidity, in ./Solidity/ folder, etc.

Please note that criticality is based on subjective appreciation. 
It should be reviewed and modified.
```
regexp,desc,level
panic!,Could generate abrupt stopings,5
unimplemented!,Could generate abrupt stopings,5
unreachable!,Could generate abrupt stopings,5
assert!,Could generate abrupt stopings,5
assert_eq!,Could generate abrupt stopings,5
assert_ne!,Could generate abrupt stopings,5
debug_assert!,Could generate abrupt stopings (only in debug mode),1
debug_assert_eq!,Could generate abrupt stopings (only in debug mode),1
debug_assert_ne!,Could generate abrupt stopings (only in debug mode),1
unsafe,Could led program to low level bugs and unhandled errors,4
extern,Could led program to low level bugs and unhandled errors,4
 {1}as {1},Potential insecure casting,2
(\w+ ?/= ?\w+)|(\w+ ?= ?\w+ ?/ ?\w+)|(\w+ ?/ ?\w+),Potential division [by zero],2
(\w+ ?\*= ?\w+)|(\w+ ?= ?\w+ ?\* ?\w+)|(\w+ ?\* ?\w+),Potential overflow,2
(\w+ ?%= ?\w+)|(\w+ ?= ?\w+ ?% ?\w+)|(\w+ ?% ?\w+),Potential overflow,2
(\w+ ?\+= ?\w+)|(\w+ ?= ?\w+ ?\+ ?\w+)|(\w+ ?\+ ?\w+)|(\w\+\+),Potential overflow,2
(\w+ ?-= ?\w+)|(\w+ ?= ?\w+ ?- ?\w+)|(\w+ ?- ?\w+)|(\w+--),Potential overflow,2
\w+\[(\w+)\],Potential index out of bounds,2
(\w+ ?>> ?\w+)|(\w+ ?<< ?\w+),Potential index out of bounds,3
todo!,Could generate abrupt stopings,5
\.unwrap,Could generate panics when unwrapping errors,3
\.unwrap–or_default\(\),Could return default values and breaks flow under certain circumstances,5
\.wrap,Could generate panics when wrapping non wrapping objects,3
expect\(,Could generate panics when wrapping non wrapping objects,3
\w+ ?= ?vec!\[0; ?\S+\],Possibility of Resource Exhaustion,5
\w+ ?= ?Vec::with_capacity\(\S+,Possibility of Resource Exhaustion,5
\w+ ?= ?read_offset\(\S+,Possibility of Resource Exhaustion,5
```

## TODO
  - [ ] At least, detect function scope
  - [ ] Detect global const and check for them in matched expressions. If a constant is divisor of a div, it should not be marked as potential div by zero
  - [ ] Add support for another languages (change use of is_comment function)
  - [x] Cargo.toml checks functionality
  - [ ] Check non-ASCII slicing