import operator


def gen(root_peg):
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
            return """c = %s (s, c);""" % self.names[peg]
        return peg.gen(self)
    def get_possible_leading_chars(self):
        return self.charset
    def sprout(self, charset):
        return Context(self.names, self.char_tests, charset)
    def gen_member_test(self, charset):
        return self.char_tests.gen_test(charset, self.charset)

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
            return 'c == %s' % c_literal_char(c)
        elif charset == set('0123456789'):
            return 'isdigit (c)'
        elif charset == set('0123456789abcdefABCDEF'):
            return 'isxdigit (c)'
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
  0,
  %s
};""" % (type, indent('\n'.join(bitmasks)))
    def _gen_bitmask(self, char_index):
        c = chr(char_index)
        bitmask = 0
        for set_index, charset in enumerate(self.sets):
            if c in charset:
                bitmask |= 1 << set_index
        return '0x%08x,' % bitmask
    def _gen_test(self, set_index):
        return 'charset_table[c+1] & (1<<%d)' % set_index
    def _enter_table(self, charset, context_charset):
        for i, set_i in enumerate(self.sets):
            if charset == set_i:
                return i
        assert all(ord(c) < 256 for c in charset)
        self.sets.append(frozenset(charset))
        return len(self.sets) - 1

prelude = """\
#include <Python.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

static PyObject *ReadError;

typedef struct {
  const char *here;
  const char *start;
  const char *end;
  int failed;
} Scanner;

static int advance (Scanner *s) {
  if (s->here == s->end) return -1;
  return 0xFF & *s->here++;
}

static void fail (Scanner *s) {
  s->here = s->end;
  s->failed = 1;  
}

static int expected (Scanner *s, int c) {
  if (0 == s->failed) {
    PyErr_Format (ReadError, "At byte-offset %d, expected '%c'",
                  s->here - s->start, c);
    fail (s);
  }
  return -1;
}

static int expected_one_of (Scanner *s, const char *charset) {
  if (0 == s->failed) {
    PyErr_Format (ReadError, "At byte-offset %d, expected one of '%s'",
                  s->here - s->start, charset);
    fail (s);
  }
  return -1;
}

static int normal_char (Scanner *s, int c) {
  if (32 <= c && c != '"' && c != '\\\\')
    return advance (s);
  else
    return expected_one_of (s, "<any non-control/non-escape character>");
}"""

def gen_prototype(name):
    return """\
static int %s (Scanner *s, int c);""" % name

def gen_function(context, peg, name):
    return """\
static int %s (Scanner *s, int c) {
  %s
  return c;
}""" % (name,
        indent(peg.gen(context)))

postlude = """\
static int parse (const char *string, const char *end) {
  Scanner scanner = { string, string, end, 0 };
  int c = g4 (&scanner, advance (&scanner));  // XXX wired-in JSON grammar production
  c = root (&scanner, c);
  c = g4 (&scanner, c);  // XXX wired-in JSON grammar production
  if (c != -1) {
    PyErr_Format (ReadError, "At byte offset %d, stuff left over", 
                  scanner.here - scanner.start);
    fail (&scanner);
  }
  return scanner.failed;
}

static PyObject *yajson_check (PyObject *self, PyObject *args) {
  (void) self;
  PyObject *string;
  if (! PyArg_ParseTuple (args, "O", &string))
    return NULL;
  char *start;
  Py_ssize_t size;
  if (-1 == PyString_AsStringAndSize(string, &start, &size)) {
      Py_DECREF(string);
      return NULL;
  }
  if (parse (start, start + size))
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


class Peg:
    pegs = ()

class Recur(Peg):
    def __init__(self, nullity, firstset):
        self.nullity  = nullity
        self.firstset = set(firstset)
        self.name     = 'root'    # XXX
    def __str__(self):
        return self.name
    def gen(self, context):
        return """c = %s (s, c);""" % self.name
    def has_null(self):
        return self.nullity
    def firsts(self):
        return self.firstset

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
            return """c = advance (s);"""
        c_lit = c_literal_char(self.c)
        return ("""if (c != %s) expected (s, %s); c = advance (s);"""
                % (c_lit, c_lit))
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
        return gen_cond(self._gen_branches(context))
    def _gen_branches(self, context):
        # context_set tracks the possible characters that have not
        # already been checked for.
        context_set = set(context.get_possible_leading_chars())
        def gen_branch(peg):
            if peg.has_null():
                return ('1', context.gen(peg))
            f = peg.firsts()
            branch = (context.gen_member_test(f),
                      context.sprout(f & context_set).gen(peg))
            context_set.difference_update(f)
            return branch
        branches = map(gen_branch, self.pegs)
        if context_set:
            # XXX fill in with self.firsts():
            branches.append(('1', """c = expected_one_of (s, "XXX");"""))
        return branches
    def has_null(self):
        return any(peg.has_null() for peg in self.pegs)
    def firsts(self):
        f = set()
        for peg in self.pegs:
            f |= peg.firsts()
        return f

def gen_cond(branches):
    # N.B. We assume the tests are known to be exhaustive, in the
    # context where they appear.
    n_possible = len(branches)
    for i, (test, stmts) in enumerate(branches):
        if test == '1':
            if stmts == ';':
                n_possible = i
            else:
                n_possible = i + 1
            break
    branches = branches[:n_possible]
    if not branches:
        return ';'
    elif 1 == len(set(stmts for (test, stmts) in branches)):
        test = ' || '.join(test for (test, stmts) in branches)
        return gen_if(test, branches[0][1])
    else:
        return '\nelse '.join(gen_if(test, stmts) for (test, stmts) in branches)

def gen_if(test, stmts):
    return """\
if (%s) {
  %s
}""" % (test, indent(stmts))

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
    def gen(self, context):
        return ("""\
while (%s) {
  %s
}""" % (context.gen_member_test(self.peg.firsts()),
        indent(context.gen(self.peg))))
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
    def gen(self, context):
        context = context.sprout(all_chars)
        return ("""\
for (;;) {
  %s
  if (!(%s)) break;
  %s
}""" % (indent(context.gen(self.peg)),
        context.gen_member_test(self.separator.firsts()),
        indent(context.gen(self.separator))))
    def has_null(self):
        return False
    def firsts(self):
        return Seq(self.peg, self.separator).firsts()

class NormalChar(Peg):
    # unich = <any unicode character except '"' or '\' or a control character>
    def __str__(self):
        return 'u'
    def gen(self, context):
        return 'c = normal_char (s, c);'
    def has_null(self):
        return False
    def firsts(self):
        f = set(chr(i) for i in range(32, 256))
        f.remove('"')
        f.remove('\\')
        f.remove(chr(127))      # I think this counts as a control character
        return f


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


c_escape_table = {
    "'":  "'",
    '\\': '\\',
    '\b': 'b',
    '\f': 'f',
    '\n': 'n',
    '\r': 'r',
    '\t': 't',
    # XXX anything else?
    }
def c_literal_char(c):
    assert 1 == len(c)
    if c in c_escape_table:
        return r"'\%s'" % c_escape_table[c]
    elif ord(c) < 32 or 127 <= ord(c):
        assert ord(c) <= 255
        return r"(0xFF & '\x%02x')" % ord(c)
    else:
        return "'%s'" % c

def indent(string):
    return string.replace('\n', '\n  ')
