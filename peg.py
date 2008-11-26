import operator


def gen(root_peg):
    """Return C source code for a C-Python API module providing a
    matcher against root_peg. Currently a bit of the code assumes
    root_peg is a JSON grammar: it knows that the jvalue production
    happens to work out to the generated name of g2, for the initial
    entry point. Needs generalizing! More seriously, we also can't
    match the null byte, we don't memoize, and there's at least one
    JSON-grammar-specific assumption I've let creep in, something like
    the LL(1) grammar condition: that once a sub-peg matches the
    leading character of its input, then its failure to match on
    further input implies that the whole top-level expression must
    fail to match. I don't think it'd be *hard* to relax this
    assumption, but it might pervasively affect the C code scheme.
    Also, the inlining heuristic will produce code-size blowup on
    some grammars; to avoid this we'd need a more conservative
    definition of triviality.

    On the plus side, the generated code is really fast. I think all
    of the optimizations I've included have been tested to actually
    speed it up in practice."""
    check_for_nulls(root_peg)
    # 'names' assigns names to the pegs we won't inline. We inline
    # all pegs that are either trivial or referenced just once.
    names = gen_names(count_em(root_peg))
    nameitems = (sorted(names.items(), key=operator.itemgetter(1))
                 + [(root_peg, 'root')])
    protos = '\n'.join(gen_prototype(name) for peg, name in nameitems)
    char_tests = CharTests()
    context = Context(names, char_tests, all_chars)
    functions = '\n\n'.join(gen_function(context, peg, name)
                            for peg, name in nameitems)
    return '\n\n'.join([prelude, char_tests.gen_tables(), 
                        protos, functions, postlude])

all_chars = set(map(chr, range(0, 256)))

class Context:
    """The context of code generation. It changes as we go. It
    includes the generated names of functions implementing nontrivial
    productions, the set of constant tables used by char-set
    membership tests, and contextual knowledge of what the next input
    character may possibly be at the current point in the code
    (because prior tests rule some characters out)."""
    def __init__(self, names, char_tests, charset):
        self.names      = names
        self.char_tests = char_tests
        self.charset    = charset
    def gen(self, peg):
        if peg in self.names:
            return gen_call(self.names[peg], peg)
        return peg.gen(self)
    def get_possible_leading_chars(self):
        return self.charset
    def sprout(self, charset):
        return Context(self.names, self.char_tests, charset)
    def gen_member_test(self, charset):
        return self.char_tests.gen_test(charset, self.charset)
    def gen_advance(self):
        # N.B. The correctness of this depends on two facts:
        #  - We always exit immediately on error.
        #  - A test against the null-terminator of the input string is
        #    always an error. We know this because check_for_nulls(root_peg).
        return 'c = *++z;'

class CharTests:
    """Picks the cheapest way to test for character-set membership in
     a context. This may turn out to be by lookup in a constant table,
     which this object remembers and generates."""
    def __init__(self):
        self.sets = [] # Those sets that need a table for membership tests.
    def gen_test(self, charset, context_charset):
        """Return a C expression that's true iff the variable 'c'
        is a member of charset, given we already know c is a 
        member of context_charset."""
        # TODO: extract most of this logic into another function.
        # This object should only be responsible for constant-table
        # tests. (I think.)
        assert charset.issubset(context_charset)
        test_set = charset & context_charset
        if not test_set:
            return '0'
        elif context_charset.issubset(charset):
            return '1'
        elif 1 == len(test_set):
            c = list(test_set)[0]
            return 'c == %s' % c_char_literal(c)
        elif 1 == len(context_charset - charset):
            inverse = context_charset - charset
            c = list(inverse)[0]
            return 'c != %s' % c_char_literal(c)
        elif charset == set('0123456789'):  # & context_charset
            return 'isdigit (c)'
        elif charset == set('0123456789abcdefABCDEF'):  # & context_charset
            return 'isxdigit (c)'
        elif get_nonempty_range(charset):
            # A range test is not necessarily faster in itself than a
            # table test, but it conserves space for the irregular
            # sets that actually need tables. (When we have fewer 
            # tables, accessing each one is faster.)
            return gen_range_test(get_nonempty_range(charset))
        else:
            return self._gen_test(self._enter_table(charset, context_charset))
    def gen_tables(self):
        """Return C declarations of any tables needed by expressions
        we've emitted for self.gen_test()."""
        assert len(self.sets) <= 32 # XXX relax this restriction
        if len(self.sets) <= 8:
            type = 'unsigned char'
        elif len(self.sets) <= 16:
            type = 'unsigned short'
        else:
            type = 'unsigned'
        bitmasks = map(self._gen_bitmask, range(256))
        return """\
static const %s charset_table[256] = {
  %s
};""" % (type, indent('\n'.join(bitmasks)))
    def _gen_bitmask(self, char_index):
        c = chr(char_index)
        bitmask = 0
        for set_index, charset in enumerate(self.sets):
            if c in charset:
                bitmask |= 1 << set_index
        return '0x%0*x,' % ((len(self.sets) + 3) >> 2, bitmask)
    def _gen_test(self, set_index):
        return 'charset_table[c] & (1<<%d)' % set_index
    def _enter_table(self, charset, context_charset):
        for i, set_i in enumerate(self.sets):
            if charset == set_i:
                return i
        assert all(ord(c) < 256 for c in charset) # XXX relax this restriction
        self.sets.append(frozenset(charset))
        return len(self.sets) - 1

def get_nonempty_range(charset):
    """Return x,y such that charset == set(map(chr, range(x, y))),
    if possible (and nonempty), else None."""
    if not charset:
        return None
    vs = map(ord, sorted(charset))
    lo, hi = vs[0], vs[-1]
    if hi + 1 - lo == len(charset):
        return lo, hi + 1
    return None

def gen_range_test((lo, hibound)):
    # TODO: generate a > test when hibound == 256
    return '(unsigned)(c - %u) < %u' % (lo, hibound - lo)
    

prelude = """\
#include <Python.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

static PyObject *ReadError;

typedef unsigned char u8;

typedef struct {
  const u8 *start;
  const u8 *end;
} Scanner;

static const u8 *expected (Scanner *s, const u8 *z, char c) {
  PyErr_Format (ReadError, "At byte-offset %d, expected '%c'",
                z - s->start, c);
  return NULL;
}

static const u8 *expected_one_of (Scanner *s, const u8 *z, const char *charset) {
  PyErr_Format (ReadError, "At byte-offset %d, expected one of '%s'",
                z - s->start, charset);
  return NULL;
}"""

def gen_prototype(name):
    return """\
static const u8 *%s (Scanner *s, const u8 *z);""" % name

def gen_function(context, peg, name):
    return """\
static const u8 *%s (Scanner *s, const u8 *z) {
  u8 c = *z;
  %s
  return z;
}""" % (name,
        indent(peg.gen(context)))

postlude = """\
static int parse (const u8 *string, const u8 *end) {
  Scanner scanner = { string, end };
  const u8 *z = string;
  z = g2 (&scanner, z); // XXX wired-in JSON grammar production
  z = root (&scanner, z); if (!z) return 1;
  z = g2 (&scanner, z); // XXX wired-in JSON grammar production
  if (z != end) {
    PyErr_Format (ReadError, "At byte offset %d, stuff left over", 
                  z - scanner.start);
    return 1;
  }
  return 0;
}

static PyObject *yajson_check (PyObject *self, PyObject *args) {
  (void) self;
  PyObject *string;
  if (! PyArg_ParseTuple (args, "O", &string))
    return NULL;
  char *start;
  Py_ssize_t size;
  if (-1 == PyString_AsStringAndSize (string, &start, &size)) {
      Py_DECREF (string);
      return NULL;
  }
  if (parse ((const u8 *)start, (const u8 *)start + size))
    return NULL;
  return PyInt_FromLong (0);
}

static PyMethodDef YajsonMethods[] = {
  {"check",    yajson_check,      METH_VARARGS, "XXX blah blah."},
  {NULL,       NULL,               0,            NULL}
};

void inityajson (void) {
  PyObject *module = Py_InitModule ("yajson", YajsonMethods);
  if (module == NULL)
    return;
  ReadError = PyErr_NewException ("yajson.ReadError", PyExc_ValueError, NULL);
  if (ReadError == NULL)
    return;
  Py_INCREF (ReadError);
  PyModule_AddObject (module, "ReadError", ReadError);
}"""

def gen_names(pegs):
    "Return a map from the nontrivial pegs to their generated names."
    pegs = [peg for peg in pegs if not peg.is_trivial()]
    return dict((peg, 'g%d' % i) 
                for (i, peg) in enumerate(sorted(pegs, key=str)))

def count_em(root_peg):
    """Return a set of those pegs referenced more than once in the
    graph reachable from root_peg."""
    seen = set()
    multiples = set()
    def counting(peg):
        if peg in seen:
            multiples.add(peg)
        else:
            seen.add(peg)
            map(counting, peg.pegs)
    counting(root_peg)
    return multiples

def check_for_nulls(peg):
    """Crash if any reachable peg can match the null byte. Needed
    because we generate code using the null byte as an end-of-input
    sentinel, assuming such a null byte is never accepted. (This
    happens to be a speed win with the C-Python API.)"""
    assert chr(0) not in peg.firsts()
    map(check_for_nulls, peg.pegs)


class Peg:
    "A part of a Parsing Expression Grammar."
    pegs = ()
    def is_trivial(self):
        """A trivial peg has no * or any sub-pegs except literals.
        It's equivalent to a union of literal strings."""
        return all(isinstance(peg, Literal) for peg in self.pegs)
    def gen(self, context):
        """Return C code (a sequence of statements) for this peg to
        match the input."""
        abstract
    def has_null(self):
        "Return true iff this peg can match the empty string."
        abstract
    def firsts(self):
        """Return a set including all characters that can possibly
        appear as the first character of input that this peg matches."""
        abstract
    def can_overcommit(self):
        """Return true unless it's guaranteed that matching this peg
        never needs to backtrack. That is: unless, once the first
        character is matched, this peg is certain to match
        something."""
        abstract

class Recur(Peg):
    """A PEG grammar may include recursive productions. Implemented
    directly, this would mean cycles in our reference graph, plus the
    need to solve simultaneous equations to compute the first-sets.
    Instead, we make the user represent the references to the recurring
    production as Recur nodes. The user must supply the solution to
    the recursion equations. (Not onerous for a simple grammar like
    JSON. Later on we can add code to compute it ourselves if this
    library ever gets that far.)"""
    def __init__(self, nullity, firstset, variables):
        self.nullity   = nullity
        self.firstset  = set(firstset)
        self.name      = 'root'    # XXX
        self.variables = tuple(variables)
    def __str__(self):
        return self.name
    def gen(self, context):
        return gen_call(self.name, self)
    def has_null(self):
        return self.nullity
    def firsts(self):
        return self.firstset
    def can_overcommit(self):
        return True

def gen_call(name, peg):
    if always_succeeds(peg):
        return 'z = %s (s, z); c = *z;' % name
    else:
        return 'z = %s (s, z); if (!z) return z; c = *z;' % name

def always_succeeds(peg):
    return peg.has_null() and not peg.can_overcommit()

class Epsilon(Peg):
    "A peg that matches just the empty string."
    def __str__(self):
        return '()'
    def gen(self, context):
        return ';'
    def has_null(self):
        return True
    def firsts(self):
        return set()
    def can_overcommit(self):
        return False

class Code(Epsilon):
    "A 'peg' that succeeds and performs some C-code action."
    # XXX all this needs filling out with a way to return parse results
    def __init__(self, body):
        self.body = body
    def __str__(self):
        return '{%s}' % self.body
    def gen(self, context):
        return self.body

class Variable:
    "A C-code variable, to be assigned to in Code pegs."
    def __init__(self, name, type, initial_value):
        self.name = name
        self.type = type
        self.initial_value = initial_value
    def __str__(self):
        return self.name
    def gen_init(self):
        return '%s %s = %s;' % (self.type, self.name, self.initial_value)
    def gen_finalize(self):
        if self.type == 'PyObject*':
            return 'if (%s) { Py_DECREF (%s); }' % (self.name, self.name)
        return ';'

class Scope(Peg):
    "A peg that introduces local variables with scope enclosing the sub-peg."
    def __init__(self, variables, peg):
        self.variables = variables
        self.peg  = peg
        self.pegs = (peg,)
    def __str__(self):
        return '[%s|%s]' % (','.join(map(str, self.variables)), self.peg)
    def gen(self, context):
        # XXX needs cleanup, etc.
        return ('{\n  %s\n  %s\n  %s\n}'
                % (indent('\n'.join(v.gen_init()
                                    for v in self.variables)),
                   indent(self.peg.gen(context)),
                   indent('\n'.join(v.gen_finalize()
                                    for v in self.variables))))
    def has_null(self):
        return self.peg.has_null()
    def firsts(self):
        return self.peg.firsts()
    def can_overcommit(self):
        return self.peg.can_overcommit()

class Literal(Peg):
    "A peg that matches a single literal character."
    def __init__(self, c):
        assert 1 == len(c)
        self.c = c
    def __str__(self):
        return "'%s'" % self.c
    def gen(self, context):
        if set(self.c) == context.get_possible_leading_chars():
            return context.gen_advance()
        c_lit = c_char_literal(self.c)
        return ("""if (c != %s) return expected (s, z, %s); %s"""
                % (c_lit, c_lit, context.gen_advance()))
    def has_null(self):
        return False
    def firsts(self):
        return set(self.c)
    def can_overcommit(self):
        return False

class OneOf(Peg):
    "A peg that matches if any of its sub-pegs matches."
    def __init__(self, *pegs):
        assert 0 < len(pegs)
        self.pegs = map(parse, pegs)
    def __str__(self):
        return '(%s)' % '|'.join(map(str, self.pegs))
    def gen(self, context):
        return gen_dispatch(context, self._gen_branches(context))
    def _gen_branches(self, context):
        # context_set tracks the possible characters that have not
        # already been checked for.
        context_set = set(context.get_possible_leading_chars())
        def gen_branch(peg):
            cs = frozenset(context_set)
            if peg.has_null():
                return (cs, cs, context.gen(peg))
            f = peg.firsts()
            branch = (cs, f, context.sprout(f & cs).gen(peg))
            context_set.difference_update(f)
            return branch
        branches = map(gen_branch, self.pegs)
        if context_set:
            # XXX fill in with self.firsts():
            cs = frozenset(context_set)
            expected = sorted(self.firsts())
            branches.append((cs, cs, ('return expected_one_of (s, z, %s);'
                                      % c_string_literal(expected))))
        return branches
    def has_null(self):
        return any(peg.has_null() for peg in self.pegs)
    def firsts(self):
        return union(peg.firsts() for peg in self.pegs)
    def can_overcommit(self):
        return any(peg.can_overcommit() for peg in self.pegs)

def union(sets):
    result = set()
    for s in sets:
        result |= s
    return result

def gen_dispatch(context, branches):
    """Generate an if...else-if chain."""
    # N.B. We assume the tests are known to be exhaustive in the given context.
    branches = truncate(collapse(branches))
    if len(branches) == 0:
        return ';'
    elif len(branches) <= 3:
        return '\nelse '.join(
            gen_if(context.sprout(context_set).gen_member_test(charset),
                   stmts)
            for (context_set, charset, stmts) in branches)
    else:
        return """\
switch (c) {
  %s
}""" % indent('\n'.join(gen_case(context, branch) for branch in branches))

def gen_case(context, (context_set, charset, stmts)):
    if context_set.issubset(charset):
        label = 'default:'
    else:
        label = '\n'.join('case %s:' % c_char_literal(c)
                          for c in sorted(charset))
    return '%s\n  %s\n  break;' % (label, indent(stmts))

def truncate(branches):
    "Remove any branches that are always preempted by earlier branches."
    result = []
    for context_set, charset, stmts in branches:
        always_taken = context_set.issubset(charset)
        if not always_taken or stmts != ';':
            result.append((context_set, charset, stmts))
        if always_taken:
            break
    return result

def collapse(branches):
    "Combine adjacent branches that share the same body."
    result = []
    prev_stmts = None
    for context_set, charset, stmts in branches:
        if stmts == prev_stmts:
            prev_context_set, prev_charset, _ = result[-1]
            result[-1] = prev_context_set, prev_charset | charset, prev_stmts
        else:
            result.append((context_set, charset, stmts))
            prev_stmts = stmts
    return result

def gen_if(test, stmts):
    stmts = embrace(stmts)
    if test == '1':
        return stmts
    return 'if (%s) %s' % (test, stmts)

def embrace(stmts):
    # XXX why is this a bug? --
    #if stmts.startswith('{') and stmts.endswith('}'):
    #    return stmts
    return '{\n  %s\n}' % indent(stmts)

class Seq(Peg):
    """A peg that matches any concatenation of what each of its
    sub-pegs matches, in order."""
    def __init__(self, *pegs):
        self.pegs = map(parse, pegs)
    def __str__(self):
        return '(%s)' % ';'.join(map(str, self.pegs))
    def gen(self, context):
        stmts = []
        c = context
        for peg in self.pegs:
            stmts.append(c.gen(peg))
            # TODO: follow-sets can be narrower than all_chars
            c = context.sprout(all_chars)
        return '\n'.join(stmts)
    def has_null(self):
        return all(peg.has_null() for peg in self.pegs)
    def firsts(self):
        f = set()
        for peg in self.pegs:
            f |= peg.firsts()
            if not peg.has_null():
                break
        return f
    def can_overcommit(self):
        return True             # (conservative)

class Star(Peg):
    """A peg that matches any concatenation of 0 or more matches
    by its sub-peg. (Kleene star.)"""
    def __init__(self, peg):
        self.peg = parse(peg)
        self.pegs = (self.peg,)
    def __str__(self):
        return '*(%s)' % self.peg
    def is_trivial(self):
        return False
    def gen(self, context):
        assert not self.peg.has_null()
        f = self.peg.firsts()
        return ("""\
while (%s) {
  %s
}""" % (context.gen_member_test(f),
        indent(context.sprout(f).gen(self.peg))))
    def has_null(self):
        return True
    def firsts(self):
        return self.peg.firsts()
    def can_overcommit(self):
        return self.peg.can_overcommit()

class StarSep(Peg):
    """A peg that matches like (p (sep p)*). That is,
    StarSep(p, sep) is equivalent to Seq(p, Star(seq(sep, p))).
    sep must not match the empty string."""
    # I think I provided this class because it's easier to make this
    # primitive than to generate good code for the combination. I
    # don't remember for sure...
    def __init__(self, peg, separator):
        self.peg = parse(peg)
        self.separator = parse(separator)
        # XXX aren't we missing an "assert not self.peg.has_null()"?
        assert not self.separator.has_null()
        self.pegs = (self.peg, self.separator)
    def __str__(self):
        return '(%s@%s)' % self.pegs
    def is_trivial(self):
        return False
    def gen(self, context):
        context = context.sprout(all_chars)
        sf = self.separator.firsts()
        return ("""\
for (;;) {
  %s
  if (!(%s)) break;
  %s
}""" % (indent(context.gen(self.peg)),
        context.gen_member_test(sf),
        indent(context.sprout(sf).gen(self.separator))))
    def has_null(self):
        return False
    def firsts(self):
        return Seq(self.peg, self.separator).firsts()
    def can_overcommit(self):
        return True             # only slightly conservative

def Maybe(peg):
    "Matching peg or the empty string."
    return OneOf(peg, Epsilon())


def parse(surface_peg):
    "Convert from a convenient 'surface syntax' to a peg object."
    if isinstance(surface_peg, basestring):
        return one_of(map(Literal, surface_peg))
    return surface_peg

def one_of(pegs):
    assert 0 < len(pegs)
    if 1 == len(pegs):
        return pegs[0]
    return OneOf(*pegs)


def c_char_literal(c):
    "Convert c to a C constant expression of type unsigned char."
    esc = c_escape(c, "'")
    if 0x80 <= ord(c):
        return r"((u8)'%s')" % esc
    return r"'%s'" % esc

def c_string_literal(s):
    "Convert s to a C constant string."
    return '"%s"' % ''.join(c_escape(c, '"') for c in s)

c_escape_table = {
    '\\': '\\',
    '\a': 'a',
    '\b': 'b',
    '\f': 'f',
    '\n': 'n',
    '\r': 'r',
    '\t': 't',
    '\v': 'v',
    }
def c_escape(c, delimiter):
    assert 1 == len(c)
    if c == delimiter:
        return '\\' + c
    if c in c_escape_table:
        return '\\' + c_escape_table[c]
    elif ord(c) < 32 or 127 <= ord(c):
        assert ord(c) <= 255
        return '\\x%02x' % ord(c)
    else:
        return c

def indent(string):
    return string.replace('\n', '\n  ')
