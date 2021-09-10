# Merkle tree library in OCaml.

A library that represents the Merkle tree data structure in ocaml, the library allows to : 

- Create a merkle tree from a list of elements.
- Find the minimal tree that allows to prove a given element.
- Make a merkle proof.
- Test if two merkle tree are equal
- Generate a string representation more readable of the merkle tree

### Build the library

If you just want to build the library : `dune build src/merkle.a`

### Tests

in the "test" folder, there is a test file where unit tests and property tests are written on the Merkle tree library, instantiating it with a particular context.

To execute the tests : `dune exec tests/strsha.exe`


### Dependencies (more precisely, versions of each dependencie i had when i finished the code)

- dune -> "2.9.0"
- qcheck -> "0.18"
- qcheck-alcotest -> "0.18"
- alcotest -> "1.4.0"
- odoc -> "1.5.3"
- sha -> "1.14"

### Documentation

Execute `dune build @doc` and `open _build/default/_doc/_html/index.html` for generate the documentation. The documentation of the library is in "merkle" page.