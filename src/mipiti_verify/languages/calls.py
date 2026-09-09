"""Where a value reaches a sink, per grammar: call, construction, assignment
and instantiation sites, their arguments, and what an argument IS.

The sink engine (``verifiers.sound``) asks one question of a parse tree in
any language: at every site where a value is handed to a named sink, what
is the static form of that value? This module answers it for every
tree-sitter grammar the package knows, as DATA: one :class:`CallTable`
per grammar names the node types that are calls, constructions, macros,
assignments and (for hardware description languages) module or component
instantiations; the node types that are literals, templates and
concatenations; where a callee, an argument, an assignment target or a
port connection lives. The functions below read a tree through a table,
so a new language is a new table and a new property is new parameters,
never new code.

A grammar is tabled for Verilog, SystemVerilog and VHDL exactly as for a
software language: a blocking or non-blocking assignment to a named
target is an ``assign`` sink, a module or component instantiation is an
``instantiate`` sink whose port connections are its arguments, and a
``parameter`` / ``localparam`` / ``constant`` is a named constant.

Everything here is over-approximate in the sound direction: a name is
matched on any receiver, a site the table cannot read is reported rather
than dropped, and a form the vocabulary does not name is not safe.
"""

from __future__ import annotations

from typing import Iterator, NamedTuple, Optional

from .definitions import _TS_GRAMMARS, node_text as text, walk

# The static forms the safe-form vocabulary names, plus the two outcomes a
# form can have outside it. ``constructed`` carries the boundary type it
# was built through (``constructed:<T>``) when reported.
#
# ``parameter_binding`` is never read off a node type: it is the engine's
# name for a data structure written at the site whose every element is
# itself a form the assertion admits, and it is decided from those elements
# rather than from the position the value sits in. See
# :meth:`SinkEngine.run` in ``verifiers.sound``.
FORM_LITERAL = "literal"
FORM_NAMED_CONSTANT = "named_constant"
FORM_LITERAL_CONCAT = "literal_concat"
FORM_PARAMETER_BINDING = "parameter_binding"
FORM_CONSTRUCTED = "constructed"
FORM_VIOLATION = "violation"
FORM_UNCLASSIFIABLE = "unclassifiable"

SAFE_FORMS = (FORM_LITERAL, FORM_NAMED_CONSTANT, FORM_LITERAL_CONCAT, FORM_PARAMETER_BINDING)

# The kinds of site a sink can be declared as.
KIND_CALL = "call"
KIND_CONSTRUCTOR = "constructor"
KIND_MACRO = "macro"
KIND_ASSIGN = "assign"
KIND_INSTANTIATE = "instantiate"
SINK_KINDS = (KIND_CALL, KIND_CONSTRUCTOR, KIND_MACRO, KIND_ASSIGN, KIND_INSTANTIATE)


class Form(NamedTuple):
    """The classification of one guarded value."""

    form: str        # one of the FORM_* names
    reason: str      # what was seen, for the reader
    boundary: str    # the boundary type a ``constructed`` value was built through
    # Whether the value is a data structure written at the site -- an array,
    # list, tuple, map or dictionary literal. A data structure carries its
    # elements, and an element of it reaches the sink as surely as the
    # structure does, so being one is never on its own a reason to admit
    # the value: it only says the elements below are the values to judge.
    aggregate: bool = False
    # The static form of each element the structure was written with, in
    # source order, for an aggregate; empty for every other value. An
    # aggregate this build read no element of is empty here too, so the
    # engine treats "no element" as nothing established rather than as
    # nothing to worry about.
    elements: tuple = ()


class CallTable(NamedTuple):
    """Node types and fields the engine reads for one grammar."""

    calls: frozenset               # call node types
    callee_fields: tuple           # fields that hold the callee, in order tried
    constructors: frozenset        # construction node types (``new T(...)``)
    constructor_fields: tuple      # fields that hold the constructed type
    macros: frozenset              # macro invocation node types
    macro_fields: tuple            # fields that hold the macro name
    macro_definitions: frozenset   # macro definition node types (a body naming a sink)
    argument_lists: frozenset      # node types that list a site's arguments
    argument_wrappers: frozenset   # per-argument wrapper node types
    argument_name_fields: tuple    # fields on a wrapper that name a keyword argument
    assignments: frozenset         # assignment node types
    assignment_fields: tuple       # (target field, value field) pairs tried in order
    declarations: frozenset        # declarator node types (``name = value`` bindings)
    declaration_fields: tuple      # (name field, value field) pairs
    instantiations: frozenset      # HDL instantiation node types
    literals: frozenset            # literal node types
    templates: frozenset           # string node types that may carry substitutions
    substitutions: frozenset       # substitution node types inside a template
    concatenations: frozenset      # binary / concatenation node types
    concat_operators: frozenset    # operator tokens that concatenate
    aggregates: frozenset          # array / list / map / tuple literal node types
    identifiers: frozenset         # identifier node types
    imports: frozenset             # import / use node types (names there are bindings, not escapes)
    aliases: frozenset             # import-alias node types: (source field, alias field) below
    alias_fields: tuple
    constants: frozenset           # declaration node types that may bind a named constant
    constant_modifiers: frozenset  # modifier tokens required for a constant (empty = none)
    constant_any_value: bool       # every binding of the kind is a constant, whatever its value (HDL parameters)
    parameters: frozenset          # parameter list node types under a definition
    escapes: dict                  # callee leaf -> index of the argument that must be a literal
    variable_callee: frozenset     # callee node types that are a variable (a call through a value)
    hdl: bool


def _t(
    calls=(), callee_fields=("function", "name", "method", "procedure", "constructor", "macro"),
    constructors=(), constructor_fields=("type", "constructor", "name"),
    macros=(), macro_fields=("macro", "name"), macro_definitions=(),
    argument_lists=(), argument_wrappers=(), argument_name_fields=("name",),
    assignments=(), assignment_fields=(("left", "right"), ("target", "value"), ("target", "result")),
    declarations=(), declaration_fields=(("name", "value"), ("pattern", "value"), ("declarator", "value")),
    instantiations=(), literals=(), templates=(), substitutions=(),
    concatenations=(), concat_operators=("+",), aggregates=(), identifiers=(), imports=(), aliases=(),
    alias_fields=(("name", "alias"), ("path", "alias")), constants=(), constant_modifiers=(),
    constant_any_value=False, parameters=(), escapes=None, variable_callee=(), hdl=False,
) -> CallTable:
    return CallTable(
        frozenset(calls), tuple(callee_fields), frozenset(constructors), tuple(constructor_fields),
        frozenset(macros), tuple(macro_fields), frozenset(macro_definitions),
        frozenset(argument_lists), frozenset(argument_wrappers), tuple(argument_name_fields),
        frozenset(assignments), tuple(assignment_fields), frozenset(declarations),
        tuple(declaration_fields), frozenset(instantiations), frozenset(literals),
        frozenset(templates), frozenset(substitutions), frozenset(concatenations),
        frozenset(concat_operators), frozenset(aggregates),
        frozenset(identifiers), frozenset(imports), frozenset(aliases),
        tuple(alias_fields), frozenset(constants), frozenset(constant_modifiers), constant_any_value,
        frozenset(parameters), dict(escapes or {}), frozenset(variable_callee), hdl,
    )


_JS_TABLE = _t(
    calls=("call_expression",),
    constructors=("new_expression",),
    argument_lists=("arguments",),
    assignments=("assignment_expression", "augmented_assignment_expression"),
    declarations=("variable_declarator",),
    literals=("string", "number", "true", "false", "null", "undefined", "regex"),
    templates=("template_string", "string"),
    substitutions=("template_substitution",),
    concatenations=("binary_expression",),
    aggregates=("array", "object"),
    identifiers=("identifier", "property_identifier", "shorthand_property_identifier"),
    imports=("import_statement",),
    aliases=("import_specifier", "namespace_import"),
    constants=("lexical_declaration",),
    constant_modifiers=("const",),
    parameters=("formal_parameters",),
    escapes={"eval": 0, "Function": 0},
)

_TS_TABLES: dict[str, CallTable] = {
    "javascript": _JS_TABLE,
    "typescript": _JS_TABLE,
    "tsx": _JS_TABLE,
    "go": _t(
        calls=("call_expression",),
        argument_lists=("argument_list",),
        assignments=("assignment_statement", "short_var_declaration"),
        declarations=("var_spec", "const_spec"),
        literals=("interpreted_string_literal", "raw_string_literal", "int_literal", "float_literal",
                  "rune_literal", "imaginary_literal", "true", "false", "nil"),
        concatenations=("binary_expression",),
        aggregates=("composite_literal",),
        identifiers=("identifier", "field_identifier", "package_identifier", "type_identifier"),
        imports=("import_declaration",),
        aliases=("import_spec",),
        alias_fields=(("path", "name"),),
        constants=("const_spec",),
        parameters=("parameter_list",),
        escapes={"MethodByName": 0, "FieldByName": 0},
    ),
    "rust": _t(
        calls=("call_expression",),
        macros=("macro_invocation",),
        argument_lists=("arguments", "token_tree"),
        assignments=("assignment_expression", "compound_assignment_expr"),
        declarations=("let_declaration",),
        literals=("string_literal", "raw_string_literal", "integer_literal", "float_literal",
                  "boolean_literal", "char_literal"),
        concatenations=("binary_expression",),
        aggregates=("array_expression", "tuple_expression"),
        identifiers=("identifier", "field_identifier", "type_identifier"),
        imports=("use_declaration",),
        aliases=("use_as_clause",),
        constants=("const_item", "static_item"),
        parameters=("parameters",),
        escapes={},
    ),
    "java": _t(
        calls=("method_invocation",),
        constructors=("object_creation_expression",),
        argument_lists=("argument_list",),
        assignments=("assignment_expression",),
        declarations=("variable_declarator",),
        literals=("string_literal", "text_block", "decimal_integer_literal", "hex_integer_literal",
                  "octal_integer_literal", "binary_integer_literal", "decimal_floating_point_literal",
                  "hex_floating_point_literal", "character_literal", "true", "false", "null_literal"),
        concatenations=("binary_expression",),
        aggregates=("array_creation_expression", "array_initializer"),
        identifiers=("identifier", "type_identifier"),
        imports=("import_declaration",),
        constants=("field_declaration",),
        constant_modifiers=("final",),
        parameters=("formal_parameters",),
        escapes={"forName": 0, "getMethod": 0, "getDeclaredMethod": 0, "loadClass": 0, "invoke": 0},
    ),
    "kotlin": _t(
        calls=("call_expression",),
        callee_fields=(),
        argument_lists=("value_arguments",),
        argument_wrappers=("value_argument",),
        assignments=("assignment",),
        declarations=("property_declaration",),
        literals=("string_literal", "integer_literal", "long_literal", "real_literal", "hex_literal",
                  "bin_literal", "boolean_literal", "character_literal", "null_literal",
                  "unsigned_literal"),
        templates=("string_literal",),
        substitutions=("interpolated_identifier", "interpolated_expression"),
        concatenations=("additive_expression",),
        identifiers=("simple_identifier", "type_identifier"),
        imports=("import_header",),
        constants=("property_declaration",),
        constant_modifiers=("const", "val"),
        parameters=("function_value_parameters",),
        escapes={"forName": 0, "getMethod": 0, "getDeclaredMethod": 0, "invoke": 0},
    ),
    "c": _t(
        calls=("call_expression",),
        macro_definitions=("preproc_def", "preproc_function_def"),
        argument_lists=("argument_list",),
        assignments=("assignment_expression",),
        declarations=("init_declarator",),
        literals=("string_literal", "concatenated_string", "number_literal", "char_literal",
                  "true", "false", "null"),
        identifiers=("identifier", "field_identifier", "type_identifier"),
        imports=("preproc_include",),
        constants=("declaration", "preproc_def"),
        constant_modifiers=("const",),
        parameters=("parameter_list",),
        escapes={"dlsym": 1},
    ),
    "cpp": _t(
        calls=("call_expression",),
        constructors=("new_expression",),
        macro_definitions=("preproc_def", "preproc_function_def"),
        argument_lists=("argument_list", "initializer_list"),
        assignments=("assignment_expression",),
        declarations=("init_declarator",),
        literals=("string_literal", "concatenated_string", "raw_string_literal", "number_literal",
                  "char_literal", "user_defined_literal", "true", "false", "null", "nullptr"),
        concatenations=("binary_expression",),
        identifiers=("identifier", "field_identifier", "type_identifier", "namespace_identifier"),
        imports=("preproc_include", "using_declaration"),
        constants=("declaration", "preproc_def"),
        constant_modifiers=("const", "constexpr"),
        parameters=("parameter_list",),
        escapes={"dlsym": 1},
    ),
    "csharp": _t(
        calls=("invocation_expression",),
        constructors=("object_creation_expression",),
        argument_lists=("argument_list",),
        argument_wrappers=("argument",),
        assignments=("assignment_expression",),
        declarations=("variable_declarator",),
        literals=("string_literal", "verbatim_string_literal", "raw_string_literal", "integer_literal",
                  "real_literal", "character_literal", "boolean_literal", "null_literal"),
        templates=("interpolated_string_expression",),
        substitutions=("interpolation",),
        concatenations=("binary_expression",),
        aggregates=("implicit_array_creation_expression", "array_creation_expression",
                    "initializer_expression", "collection_expression"),
        identifiers=("identifier",),
        imports=("using_directive",),
        constants=("field_declaration",),
        constant_modifiers=("const", "readonly"),
        parameters=("parameter_list",),
        escapes={"GetType": 0, "Load": 0, "GetMethod": 0, "Invoke": 0},
    ),
    "ruby": _t(
        calls=("call", "command_call"),
        argument_lists=("argument_list",),
        assignments=("assignment",),
        declarations=(),
        literals=("string", "integer", "float", "true", "false", "nil", "simple_symbol", "symbol",
                  "heredoc_beginning", "character"),
        templates=("string", "heredoc_body"),
        substitutions=("interpolation",),
        concatenations=("binary",),
        aggregates=("array", "hash"),
        identifiers=("identifier", "constant"),
        imports=(),
        constants=("assignment",),
        parameters=("method_parameters", "parameters", "block_parameters"),
        escapes={"eval": 0, "instance_eval": 0, "class_eval": 0, "module_eval": 0, "send": 0,
                 "public_send": 0, "const_get": 0, "instance_variable_get": 0},
    ),
    "php": _t(
        calls=("function_call_expression", "member_call_expression", "scoped_call_expression",
               "nullsafe_member_call_expression"),
        constructors=("object_creation_expression",),
        argument_lists=("arguments",),
        argument_wrappers=("argument",),
        assignments=("assignment_expression",),
        declarations=(),
        literals=("string", "encapsed_string", "integer", "float", "boolean", "null", "heredoc",
                  "nowdoc"),
        templates=("encapsed_string", "heredoc"),
        substitutions=("variable_name", "member_access_expression", "subscript_expression",
                       "encapsed_string_interpolation"),
        concatenations=("binary_expression",),
        concat_operators=(".", "+"),
        aggregates=("array_creation_expression",),
        identifiers=("name", "variable_name"),
        imports=("namespace_use_declaration",),
        constants=("const_element",),
        parameters=("formal_parameters",),
        escapes={"eval": 0, "call_user_func": 0, "call_user_func_array": 0, "create_function": 1},
        variable_callee=("variable_name", "member_access_expression", "subscript_expression"),
    ),
    "swift": _t(
        calls=("call_expression",),
        callee_fields=(),
        argument_lists=("value_arguments",),
        argument_wrappers=("value_argument",),
        assignments=("assignment",),
        declarations=("property_declaration",),
        literals=("line_string_literal", "multi_line_string_literal", "raw_string_literal",
                  "integer_literal", "real_literal", "hex_literal", "oct_literal", "bin_literal",
                  "boolean_literal", "nil"),
        templates=("line_string_literal", "multi_line_string_literal"),
        substitutions=("interpolated_expression",),
        concatenations=("additive_expression",),
        aggregates=("array_literal", "dictionary_literal"),
        identifiers=("simple_identifier", "type_identifier"),
        imports=("import_declaration",),
        constants=("property_declaration",),
        constant_modifiers=("let",),
        parameters=("parameter",),
        escapes={"NSClassFromString": 0, "NSSelectorFromString": 0, "perform": 0},
    ),
    "verilog": _t(
        calls=("tf_call", "system_tf_call", "method_call", "method_call_body"),
        callee_fields=(),
        argument_lists=("list_of_arguments", "list_of_arguments_parent"),
        assignments=("nonblocking_assignment", "operator_assignment", "net_assignment",
                     "variable_decl_assignment", "net_decl_assignment", "continuous_assign"),
        instantiations=("module_instantiation",),
        literals=("primary_literal", "integral_number", "decimal_number", "binary_number", "hex_number",
                  "octal_number", "string_literal", "unsigned_number", "real_number",
                  "unbased_unsized_literal", "time_literal", "constant_primary"),
        concatenations=("concatenation", "constant_concatenation", "expression"),
        concat_operators=("+", "|", "&", "^", "-", "*", "/", "%", ">>", "<<", "&&", "||"),
        identifiers=("simple_identifier", "hierarchical_identifier", "system_tf_identifier",
                     "parameter_identifier", "port_identifier", "variable_identifier",
                     "net_identifier", "hierarchical_variable_identifier", "hierarchical_net_identifier"),
        imports=("package_import_declaration", "package_import_item"),
        constants=("param_assignment", "specparam_assignment"),
        constant_any_value=True,
        parameters=("tf_port_list", "tf_port_item"),
        escapes={"$system": 0, "$readmemh": 0, "$readmemb": 0, "$fopen": 0, "$sdf_annotate": 0},
        hdl=True,
    ),
    "vhdl": _t(
        calls=("procedure_call_statement", "function_call", "ambiguous_name"),
        callee_fields=("procedure", "function", "prefix"),
        argument_lists=("association_list", "expression_list"),
        argument_wrappers=("positional_association_element", "named_association_element"),
        argument_name_fields=("formal_part",),
        assignments=("simple_waveform_assignment", "simple_concurrent_signal_assignment",
                     "simple_variable_assignment", "conditional_waveform_assignment",
                     "conditional_concurrent_signal_assignment", "selected_waveform_assignment",
                     "selected_concurrent_signal_assignment", "conditional_variable_assignment",
                     "selected_variable_assignment", "simple_force_assignment"),
        instantiations=("component_instantiation_statement",),
        literals=("string_literal", "character_literal", "bit_string_literal", "integer_decimal",
                  "real_decimal", "based_literal", "based_integer", "physical_literal", "null"),
        concatenations=("simple_expression", "expression", "term", "factor", "relation"),
        concat_operators=("&", "+", "-", "*", "/", "mod", "rem", "and", "or", "xor", "not"),
        identifiers=("identifier", "simple_name", "selected_name"),
        imports=("use_clause", "library_clause", "context_clause"),
        constants=("constant_declaration",),
        constant_any_value=True,
        parameters=("parameter_list", "interface_list"),
        escapes={},
        hdl=True,
    ),
}
_TS_TABLES["systemverilog"] = _TS_TABLES["verilog"]


def table_for(language: str) -> Optional[CallTable]:
    """The call table for a language, or ``None`` when none is tabled."""
    return _TS_TABLES.get(language)


def tabled_languages() -> tuple:
    return tuple(sorted(_TS_TABLES))


# ---------------------------------------------------------------------------
# Reading nodes
#
# A parse-tree node is a value, not a stable object: two reads of the same
# node compare equal but are not the same object, so nodes here are compared
# by ``.id`` and never by identity.
# ---------------------------------------------------------------------------

_PUNCTUATION = frozenset({"(", ")", ",", ";", ".", "->", "::", "=>", "=", ":=", "<=", "{", "}", "[", "]",
                          "#", "!", "$", "new", "map", "port", "generic"})
_WRAPPERS = frozenset({"parenthesized_expression", "argument", "value_argument", "expression",
                       "primary", "mintypmax_expression", "param_expression", "constant_expression",
                       "constant_primary", "constant_param_expression", "constant_mintypmax_expression",
                       "waveform_element", "positional_association_element", "actual_part",
                       "actual_designator", "expression_statement", "expression_list", "cast_expression",
                       "as_expression", "non_null_expression", "unary_expression", "prefix_expression",
                       "reference_expression", "await_expression", "spread_element", "argument_list"})


def named_children(node) -> list:
    return [c for c in node.children if c.is_named and c.type not in ("comment", "line_comment",
                                                                        "block_comment")]


def field(node, *names):
    """The first of ``names`` that is a field on ``node``, or ``None``."""
    for name in names:
        try:
            found = node.child_by_field_name(name)
        except Exception:  # noqa: BLE001
            found = None
        if found is not None:
            return found
    return None


def leaf_name(node, table: CallTable) -> str:
    """The last identifier a callee / target / type expression names.

    ``a.b.c`` names ``c``; ``Sink::new`` names ``new``; ``obj->run`` names
    ``run``. Read as the last identifier-typed node in document order, so
    a receiver of any shape leaves the leaf untouched.
    """
    if node is None:
        return ""
    if node.type in table.identifiers and not named_children(node):
        return text(node).strip()
    last = ""
    for n in walk(node):
        if n.type in table.identifiers and not any(c.is_named for c in n.children):
            last = text(n).strip()
    if last:
        return last
    if node.type in table.identifiers:
        return text(node).strip()
    return ""


def path_name(node, table: CallTable) -> str:
    """The dotted path a callee / target names, receivers included, with
    every separator folded to ``.`` (``Sink::new`` -> ``Sink.new``)."""
    if node is None:
        return ""
    parts = [text(n).strip() for n in walk(node)
             if n.type in table.identifiers and not any(c.is_named for c in n.children)]
    parts = [p for p in parts if p]
    if not parts:
        raw = text(node).strip()
        for sep in ("::", "->", "?."):
            raw = raw.replace(sep, ".")
        return raw
    return ".".join(parts)


def callee_of(node, table: CallTable):
    """The callee node of a call, construction or macro node."""
    if node.type in table.constructors:
        found = field(node, *table.constructor_fields)
        if found is not None:
            return found
        for child in named_children(node):
            if child.type not in table.argument_lists:
                return child
        return None
    if node.type in table.macros:
        found = field(node, *table.macro_fields)
        if found is not None:
            return found
    found = field(node, *table.callee_fields) if table.callee_fields else None
    if found is not None:
        return found
    # Grammars without a callee field (Kotlin, Swift, the HDLs): the callee is
    # the first named child that is not the argument list.
    for child in named_children(node):
        if child.type in table.argument_lists or child.type in ("call_suffix",):
            continue
        return child
    return None


class Argument(NamedTuple):
    index: int           # 0-based position among the site's arguments
    name: str            # keyword / port name, "" for a positional argument
    node: object         # the value node


def _unwrap(node, table: CallTable):
    """Strip transparent wrappers (parentheses, expression shells) down to
    the node that carries the value's form."""
    seen = 0
    while node is not None and seen < 12:
        seen += 1
        if node.type in table.literals or node.type in table.templates:
            return node
        kids = named_children(node)
        if node.type in _WRAPPERS and len(kids) == 1:
            node = kids[0]
            continue
        return node
    return node


def arguments_of(node, table: CallTable) -> list:
    """The arguments a call, construction, macro or instantiation hands over,
    in order, each with its keyword or port name when it carries one."""
    lists = []
    for n in walk(node):
        if n.id == node.id:
            continue
        if n.type in table.argument_lists or n.type == "call_suffix":
            if n.type == "call_suffix":
                continue
            # Only the site's own argument list: not one nested in an argument.
            parent = n.parent
            own = False
            while parent is not None:
                if parent.id == node.id:
                    own = True
                    break
                if parent.type in table.calls or parent.type in table.constructors or \
                        parent.type in table.macros or parent.type in table.instantiations:
                    break
                parent = parent.parent
            if own:
                lists.append(n)
    if not lists and node.type in table.macros:
        lists = [c for c in named_children(node) if c.type == "token_tree"]
    out: list = []
    index = 0
    for lst in lists:
        for child in named_children(lst):
            if child.type in table.argument_lists:
                continue
            name = ""
            value = child
            if child.type in table.argument_wrappers:
                named = field(child, *table.argument_name_fields)
                kids = named_children(child)
                if named is not None:
                    name = text(named).strip()
                    value = field(child, "value", "actual_part") or (kids[-1] if kids else child)
                elif len(kids) >= 2 and any(t.type in ("=", ":", "=>") for t in child.children) \
                        and kids[0].type in table.identifiers:
                    name = text(kids[0]).strip()
                    value = kids[-1]
                else:
                    value = field(child, "value", "actual_part") or (kids[0] if kids else child)
            elif child.type in ("named_port_connection", "named_parameter_assignment", "named_argument"):
                kids = named_children(child)
                if kids:
                    name = text(kids[0]).strip()
                    value = kids[-1] if len(kids) > 1 else child
            elif child.type in ("keyword_argument", "pair"):
                kids = named_children(child)
                if len(kids) >= 2:
                    name = text(kids[0]).strip()
                    value = kids[-1]
            out.append(Argument(index, name, _unwrap(value, table)))
            index += 1
    return out


def assignment_of(node, table: CallTable):
    """``(target node, value nodes)`` for an assignment node, else ``None``."""
    for target_field, value_field in table.assignment_fields:
        target = field(node, target_field)
        value = field(node, value_field)
        if target is not None and value is not None:
            return target, [value]
    kids = named_children(node)
    if table.hdl:
        if node.type == "continuous_assign":
            targets: list = []
            for n in walk(node):
                if n.type == "net_assignment":
                    inner = assignment_of(n, table)
                    if inner:
                        targets.append(inner)
            return targets[0] if targets else None
        if node.type == "operator_assignment":
            values = [c for c in kids if c.type not in ("variable_lvalue", "assignment_operator")]
            return (kids[0], values) if kids and values else None
        lvalue = next((c for c in kids if c.type.endswith("lvalue")), None)
        values = [] if lvalue is None else [
            c for c in kids if c.id != lvalue.id and c.type not in ("assignment_operator",)]
        if lvalue is not None and values:
            if node.type in ("variable_decl_assignment", "net_decl_assignment"):
                return None
            return lvalue, values
        if node.type in ("variable_decl_assignment", "net_decl_assignment") and len(kids) >= 2:
            return kids[0], kids[1:]
        # VHDL: target field plus waveforms
        target = field(node, "target")
        if target is not None:
            values = [n for n in walk(node) if n.type == "expression" and n.id != target.id]
            return (target, values) if values else None
        return None
    if len(kids) >= 2:
        return kids[0], [kids[-1]]
    return None


def declaration_of(node, table: CallTable):
    """``(name node, value node)`` for a declarator node, else ``None``."""
    for name_field, value_field in table.declaration_fields:
        name = field(node, name_field)
        value = field(node, value_field)
        if name is not None and value is not None:
            return name, value
    kids = named_children(node)
    if node.type == "property_declaration":  # Kotlin / Swift
        name = None
        for n in walk(node):
            if n.type in ("variable_declaration", "pattern"):
                ident = next((c for c in walk(n) if c.type in table.identifiers), None)
                if ident is not None:
                    name = ident
                    break
        value = kids[-1] if kids else None
        if name is not None and value is not None and value.id != name.id and \
                value.type not in ("modifiers", "binding_pattern_kind", "variable_declaration",
                                   "value_binding_pattern", "pattern", "type_annotation"):
            return name, value
        return None
    if node.type in ("const_spec", "var_spec"):
        name = field(node, "name")
        value = field(node, "value")
        if name is not None and value is not None:
            inner = named_children(value)
            return name, (inner[0] if value.type == "expression_list" and inner else value)
        return None
    if node.type == "variable_declarator" and len(kids) >= 2:
        return kids[0], kids[-1]
    if node.type == "const_element" and len(kids) >= 2:
        return kids[0], kids[-1]
    if node.type in ("param_assignment", "specparam_assignment") and kids:
        return kids[0], (kids[-1] if len(kids) > 1 else kids[0])
    if node.type == "constant_declaration":
        names = [n for n in walk(node) if n.type == "identifier"]
        value = next((c for c in kids if c.type in ("default_expression", "expression")), None)
        if names:
            return names[0], (value if value is not None else names[0])
        return None
    if node.type == "preproc_def":
        name = field(node, "name")
        value = field(node, "value")
        if name is not None and value is not None:
            return name, value
        return None
    if node.type == "declaration":  # C / C++: const T x = value;
        for n in walk(node):
            if n.type == "init_declarator":
                return declaration_of(n, table)
        return None
    if node.type == "field_declaration":  # Java / C#
        for n in walk(node):
            if n.type == "variable_declarator":
                return declaration_of(n, table)
        return None
    if node.type == "let_declaration":
        pattern = field(node, "pattern")
        value = field(node, "value")
        if pattern is not None and value is not None:
            return pattern, value
        return None
    if node.type == "init_declarator" and len(kids) >= 2:
        return kids[0], kids[-1]
    if node.type == "assignment" and len(kids) >= 2:  # Ruby constants
        return kids[0], kids[-1]
    return None


def instantiation_of(node, table: CallTable):
    """``(type node, [Argument])`` for an HDL instantiation, else ``None``."""
    if node.type == "module_instantiation":
        type_node = field(node, "instance_type")
        if type_node is None:
            type_node = next((c for c in named_children(node) if c.type in table.identifiers), None)
        args: list = []
        index = 0
        for n in walk(node):
            if n.type == "list_of_port_connections":
                for conn in named_children(n):
                    kids = named_children(conn)
                    if conn.type == "named_port_connection":
                        name = text(kids[0]).strip() if kids else ""
                        value = field(conn, "connection") or (kids[-1] if len(kids) > 1 else None)
                    else:
                        name = ""
                        value = kids[0] if kids else None
                    if value is not None:
                        args.append(Argument(index, name, _unwrap(value, table)))
                    index += 1
        return type_node, args
    if node.type == "component_instantiation_statement":
        type_node = None
        for n in walk(node):
            if n.type in ("component_instantiation", "entity_instantiation", "configuration_instantiation"):
                type_node = field(n, "component", "entity", "configuration")
                if type_node is None:
                    type_node = next((c for c in named_children(n) if c.type in table.identifiers), None)
                break
        args: list = []
        index = 0
        for n in walk(node):
            if n.type == "port_map_aspect":
                for lst in walk(n):
                    if lst.type != "association_list":
                        continue
                    for elem in named_children(lst):
                        kids = named_children(elem)
                        formal = field(elem, "formal_part")
                        actual = field(elem, "actual_part")
                        name = text(formal).strip() if formal is not None else ""
                        value = actual if actual is not None else (kids[-1] if kids else None)
                        if value is not None:
                            args.append(Argument(index, name, _unwrap(value, table)))
                        index += 1
        return type_node, args
    return None


def definition_nodes(root, language: str) -> Iterator:
    """Every function / task / procedure definition node in a tree, with
    the name it declares and its parameter names (over-approximate: every
    identifier under the parameter list, types included)."""
    from .definitions import _node_name

    grammar = _TS_GRAMMARS.get(language)
    table = _TS_TABLES.get(language)
    if grammar is None or table is None:
        return
    kinds = set(grammar.functions) | set(grammar.methods)
    if language in ("verilog", "systemverilog"):
        kinds.add("class_constructor_declaration")
    for node in walk(root):
        if node.type not in kinds:
            continue
        name = _node_name(node, language)
        params: set = set()
        for n in walk(node):
            if n.type in table.parameters:
                for ident in walk(n):
                    if ident.type in table.identifiers and not any(c.is_named for c in ident.children):
                        params.add(text(ident).strip())
        if not params and language in ("kotlin", "swift"):
            for n in walk(node):
                if n.type in ("parameter", "function_value_parameter"):
                    for ident in walk(n):
                        if ident.type in table.identifiers:
                            params.add(text(ident).strip())
        yield node, name, params


def mentions(node, names: set, table: CallTable) -> bool:
    """Whether an expression names any of ``names`` (a parameter of the
    enclosing definition, say)."""
    if node is None or not names:
        return False
    for n in walk(node):
        if n.type in table.identifiers and text(n).strip() in names:
            return True
    return False


def is_import_context(node, table: CallTable) -> bool:
    parent = node
    while parent is not None:
        if parent.type in table.imports or parent.type in table.aliases:
            return True
        parent = parent.parent
    return False


def line_of(node) -> int:
    return node.start_point[0] + 1


# ---------------------------------------------------------------------------
# Constants and aliases
# ---------------------------------------------------------------------------

def _has_modifier(node, table: CallTable) -> bool:
    """Whether a declaration carries one of the table's constant modifiers
    (``const``, ``final``, ``let``...), read from the tokens of the node
    and its declaration ancestors up to the statement."""
    if not table.constant_modifiers:
        return True
    probe = node
    for _ in range(4):
        if probe is None:
            break
        for n in walk(probe):
            if (not n.is_named or n.type in ("modifiers", "modifier", "property_modifier",
                                             "type_qualifier", "binding_pattern_kind",
                                             "value_binding_pattern")) \
                    and text(n).strip() in table.constant_modifiers:
                return True
            if n.type in table.constant_modifiers:
                return True
        probe = probe.parent
        if probe is not None and probe.type in ("class_body", "declaration_list", "block",
                                                "statement_list", "program", "source_file",
                                                "translation_unit", "compilation_unit"):
            break
    return False


def _is_top_level(node) -> bool:
    """Whether a declaration sits at module, class or package scope rather
    than inside a function body."""
    parent = node.parent
    depth = 0
    while parent is not None and depth < 6:
        t = parent.type
        if t in ("function_body", "block", "compound_statement", "statement_list", "statements",
                 "function_statement_or_null", "seq_block", "sequence_of_statements",
                 "process_statement", "always_construct", "initial_construct",
                 "function_body_declaration", "task_body_declaration", "method_declaration",
                 "function_declaration", "function_definition", "function_item",
                 "method_definition", "arrow_function", "function_expression", "lambda_expression"):
            return False
        if t in ("program", "source_file", "translation_unit", "compilation_unit", "design_file",
                 "module_declaration", "architecture_body", "package_declaration", "package_body",
                 "class_body", "class_declaration", "declaration_list", "namespace_declaration",
                 "declarative_part", "entity_declaration", "interface_declaration",
                 "module_item", "module_or_generate_item", "package_or_generate_item_declaration"):
            return True
        parent = parent.parent
        depth += 1
    return True


def binding_counts(root, table: CallTable) -> dict:
    """How many times each name is bound (declared or assigned) in a tree,
    so a constant is one bound exactly once."""
    counts: dict = {}
    for node in walk(root):
        if node.type in table.declarations or node.type in table.constants:
            found = declaration_of(node, table)
            if found is not None:
                name = leaf_name(found[0], table)
                if name:
                    counts[name] = counts.get(name, 0) + 1
        elif node.type in table.assignments:
            found = assignment_of(node, table)
            if found is not None:
                name = leaf_name(found[0], table)
                if name:
                    counts[name] = counts.get(name, 0) + 1
    return counts


def constant_bindings(root, table: CallTable, classify) -> dict:
    """``{name: Form}`` for every name bound once, at module / class /
    package scope, to a literal (or, for an HDL parameter / constant, to
    anything: a parameter is a compile-time value by construction)."""
    counts = binding_counts(root, table)
    out: dict = {}
    for node in walk(root):
        if node.type not in table.constants:
            continue
        found = declaration_of(node, table)
        if found is None:
            continue
        name_node, value = found
        name = leaf_name(name_node, table)
        if not name or counts.get(name, 0) != 1 or not _is_top_level(node):
            continue
        if node.type == "preproc_def":
            raw = text(value).strip()
            if not (raw.startswith(('"', "'")) or raw.replace(".", "", 1).lstrip("-").isdigit()
                    or raw.lower().startswith("0x")):
                continue
            out[name] = Form(FORM_NAMED_CONSTANT, f"'#define {name}' with a literal body", "")
            continue
        if not _has_modifier(node, table):
            continue
        if table.constant_any_value:
            out[name] = Form(FORM_NAMED_CONSTANT, f"'{name}' is a declared parameter / constant", "")
            continue
        form = classify(_unwrap(value, table), {})
        if form.form == FORM_LITERAL:
            out[name] = Form(FORM_NAMED_CONSTANT, f"'{name}' is bound once to a literal", "")
    return out


def alias_bindings(root, table: CallTable, sink_leaves: set) -> dict:
    """``{alias: sink leaf}`` for every name that is bound to a sink: an
    import alias, a declaration or assignment whose value is a bare
    reference to a sink. Closed to a fixed point so an alias of an alias
    resolves."""
    aliases: dict = {}
    changed = True
    rounds = 0
    while changed and rounds < 8:
        changed = False
        rounds += 1
        known = set(sink_leaves) | set(aliases)
        for node in walk(root):
            if node.type in table.aliases:
                pairs = []
                for source_field, alias_field in table.alias_fields:
                    src = field(node, source_field)
                    alias = field(node, alias_field)
                    if src is not None and alias is not None:
                        pairs.append((src, alias))
                if not pairs:
                    kids = named_children(node)
                    if len(kids) >= 2:
                        pairs.append((kids[0], kids[-1]))
                for src, alias in pairs:
                    leaf = leaf_name(src, table)
                    alias_name = leaf_name(alias, table)
                    if leaf in known and alias_name and alias_name not in known:
                        aliases[alias_name] = aliases.get(leaf, leaf)
                        changed = True
            elif node.type in table.declarations or node.type in table.assignments:
                found = declaration_of(node, table) if node.type in table.declarations else None
                if found is None and node.type in table.assignments:
                    pair = assignment_of(node, table)
                    found = (pair[0], pair[1][0]) if pair and pair[1] else None
                if found is None:
                    continue
                name_node, value = found
                value = _unwrap(value, table)
                if value.type in table.identifiers or _is_member_reference(value, table):
                    leaf = leaf_name(value, table)
                    alias_name = leaf_name(name_node, table)
                    if leaf in known and alias_name and alias_name not in known and alias_name != leaf:
                        aliases[alias_name] = aliases.get(leaf, leaf)
                        changed = True
    return aliases


def _is_member_reference(node, table: CallTable) -> bool:
    """Whether a node is a bare dotted reference (``mod.sink``) rather than
    a call or an operation: every named descendant is an identifier."""
    kids = named_children(node)
    if not kids:
        return node.type in table.identifiers
    return all(_is_member_reference(k, table) for k in kids) and node.type not in table.calls \
        and node.type not in table.constructors and node.type not in table.literals


# ---------------------------------------------------------------------------
# Classifying a value
# ---------------------------------------------------------------------------

def classify_value(node, table: CallTable, constants: dict, boundary: dict) -> Form:
    """The static form of a value node.

    ``boundary`` is ``{"type": T, "constructors": {...}, "bound": {name: T}}``
    for a typed-boundary check (empty otherwise): a call to a declared
    constructor, or a name bound once to one, is ``constructed:<T>``.
    """
    node = _unwrap(node, table)
    if node is None:
        return Form(FORM_UNCLASSIFIABLE, "no value", "")
    t = node.type
    if t in table.templates:
        if any(n.type in table.substitutions for n in walk(node) if n.id != node.id):
            return Form(FORM_VIOLATION, f"{t} with an expression part", "")
        return Form(FORM_LITERAL, t, "")
    if t in table.literals:
        # An HDL primary may wrap an identifier; only a literal-bearing primary is a literal.
        if table.hdl and t in ("primary_literal", "constant_primary"):
            inner = [n for n in walk(node) if n.id != node.id and n.type in table.identifiers]
            if inner:
                return _classify_identifier(inner[0], table, constants, boundary)
        return Form(FORM_LITERAL, t, "")
    if t in table.identifiers or (table.hdl and t == "hierarchical_identifier"):
        return _classify_identifier(node, table, constants, boundary)
    if t in table.concatenations:
        operators = [text(c).strip() for c in node.children if not c.is_named]
        operands = named_children(node)
        if operands and (not operators or all(op in table.concat_operators for op in operators)):
            forms = [classify_value(o, table, constants, boundary) for o in operands]
            if all(f.form in (FORM_LITERAL, FORM_NAMED_CONSTANT, FORM_LITERAL_CONCAT) for f in forms):
                if len(forms) == 1:
                    return forms[0]
                return Form(FORM_LITERAL_CONCAT, "concatenation of safe operands", "")
            bad = next(f for f in forms if f.form not in (FORM_LITERAL, FORM_NAMED_CONSTANT, FORM_LITERAL_CONCAT))
            return Form(FORM_VIOLATION, f"concatenation with an unsafe operand ({bad.reason})", "")
        if operands:
            return Form(FORM_VIOLATION, f"{t} with operator {' '.join(operators) or '?'}", "")
    if boundary and (t in table.calls or t in table.constructors):
        callee = callee_of(node, table)
        leaf = leaf_name(callee, table)
        path = path_name(callee, table)
        if leaf in boundary.get("constructors", set()) or path in boundary.get("constructors", set()):
            return Form(FORM_CONSTRUCTED, f"built through {path or leaf}", boundary.get("type", ""))
    if t in table.aggregates:
        # Not a safe form on its own -- it is still an unadmitted value at a
        # guarded position. What it records is that the value is a data
        # structure written here, together with the form of each element it
        # was written with: an element reaches the sink inside the structure,
        # so the engine judges the elements rather than the container.
        elements = tuple(classify_value(e, table, constants, boundary)
                         for e in named_children(node))
        return Form(FORM_VIOLATION, f"{t} expression", "", True, elements)
    return Form(FORM_VIOLATION, f"{t} expression", "")


def _classify_identifier(node, table: CallTable, constants: dict, boundary: dict) -> Form:
    name = leaf_name(node, table)
    if name in constants:
        return constants[name]
    if boundary and name in boundary.get("bound", {}):
        return Form(FORM_CONSTRUCTED, f"'{name}' is bound once to a construction", boundary.get("type", ""))
    return Form(FORM_VIOLATION, f"identifier '{name}' is not a named constant", "")
