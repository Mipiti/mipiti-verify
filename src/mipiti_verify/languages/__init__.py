"""Language support: where a named definition lives, in any source language.

The evidence proofs (definition pin, reach, dependence) are language-agnostic
claims. This package resolves the one language-specific question they all
share -- which lines make up the definition of ``(kind, name)`` in a file --
and says how it did so, so a reader can tell an exact parser match from a
heuristic block.

- ``definitions``: the public ``locate`` / ``language_of`` / ``hash_of`` API.
- ``hdl_blocks``: keyword-pair block scanner for Verilog, SystemVerilog and
  VHDL, used when no parser is installed.
"""
