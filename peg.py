import operator


def gen(root_peg):
    check_for_nulls(root_peg)
    names = gen_names(count_em(root_peg))
    nameitems = (sorted(names.items(), key=operator.itemgetter(1))
                 + [(root_peg, 'root')])
    protos = '\n'.join(gen_prototype(name) for peg, name in nameitems)
    char_tests = CharTests()
    context = Context(names, char_tests, all_chars)
    functions = '\n\n'.join(gen_function(context, peg, name)
                            for peg, name in nameitems)
    return '\n\n'.join([prelude, char_tests.gen_tables(), protos, functions, postlude])

all_chars = set(map(chr, range(0, 256)))

class Context:
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
        #    always an error. We know this property holds because
        #    check_for_nulls(root_peg).
        return 'c = *++z;'

class CharTests:
    def __init__(self):
        self.sets = []
    def gen_test(self, charset, context_charset):
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
        elif charset == set('0123456789'):
            return 'isdigit (c)'
        elif charset == set('0123456789abcdefABCDEF'):
            return 'isxdigit (c)'
        elif get_nonempty_range(charset):
            # XXX I'm not sure this is an actual improvement:
            return gen_range_test(get_nonempty_range(charset))
        else:
            return self._gen_test(self._enter_table(charset, context_charset))
    def gen_tables(self):
        assert len(self.sets) <= 32
        if len(self.sets) <= 8:
            type = 'unsigned char'
        elif len(self.sets) <= 16:
            type = 'unsigned short'
        else:
            type = 'unsigned'
        bitmasks = map(self._gen_bitmask, range(256))
        return """\
static const %s charset_table[257] = {
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
        assert all(ord(c) < 256 for c in charset)
        self.sets.append(frozenset(charset))
        return len(self.sets) - 1

def get_nonempty_range(charset):
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
  z = g2 (&scanner, z); if (!z) return 1; // XXX wired-in JSON grammar production
  z = root (&scanner, z); if (!z) return 1;
  z = g2 (&scanner, z); if (!z) return 1; // XXX wired-in JSON grammar production
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
    pegs = [peg for peg in pegs if not peg.is_trivial()]
    return dict((peg, 'g%d' % i) 
                for (i, peg) in enumerate(sorted(pegs, key=str)))

def count_em(root_peg):
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
    # We generate code using the null byte as an end-of-input
    # sentinel, assuming such a null byte is never accepted. Check
    # this assumption.
    assert chr(0) not in peg.firsts()
    map(check_for_nulls, peg.pegs)


class Peg:
    pegs = ()
    def is_trivial(self):
        return all(isinstance(peg, Literal) for peg in self.pegs)

class Recur(Peg):
    def __init__(self, nullity, firstset):
        self.nullity  = nullity
        self.firstset = set(firstset)
        self.name     = 'root'    # XXX
    def __str__(self):
        return self.name
    def gen(self, context):
        return gen_call(self.name, self)
    def has_null(self):
        return self.nullity
    def firsts(self):
        return self.firstset

def gen_call(name, peg):
    return 'z = %s (s, z); if (!z) return z; c = *z;' % name

class Epsilon(Peg):
    def __str__(self):
        return '()'
    def gen(self, context):
        return ';'
    def has_null(self):
        return True
    def firsts(self):
        return set()

class Literal(Peg):
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

class OneOf(Peg):
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
            branches.append((cs, cs, ('return expected_one_of (s, z, %s);'
                                      % c_string_literal(sorted(self.firsts())))))
        return branches
    def has_null(self):
        return any(peg.has_null() for peg in self.pegs)
    def firsts(self):
        return union(peg.firsts() for peg in self.pegs)

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
        return '\nelse '.join(gen_if(context.sprout(context_set).gen_member_test(charset),
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
        label = '\n'.join('case %s:' % c_char_literal(c) for c in sorted(charset))
    return '%s\n  %s\n  break;' % (label, indent(stmts))

def truncate(branches):
    """Remove any branches that are always preempted by earlier branches."""
    result = []
    for context_set, charset, stmts in branches:
        always_taken = context_set.issubset(charset)
        if not always_taken or stmts != ';':
            result.append((context_set, charset, stmts))
        if always_taken:
            break
    return result

def collapse(branches):
    """Combine adjacent branches that share the same body."""
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

class Star(Peg):
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

class StarSep(Peg):
    def __init__(self, peg, separator):
        self.peg = parse(peg)
        self.separator = parse(separator)
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


def Maybe(peg):
    return OneOf(peg, Epsilon())


def parse(surface_peg):
    if isinstance(surface_peg, basestring):
        return one_of(map(Literal, surface_peg))
    return surface_peg

def one_of(pegs):
    assert 0 < len(pegs)
    if 1 == len(pegs):
        return pegs[0]
    return OneOf(*pegs)


def c_char_literal(c):
    esc = c_escape(c, "'")
    if 0x80 <= ord(c):
        return r"((u8)'%s')" % esc
    return r"'%s'" % esc

def c_string_literal(s):
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
