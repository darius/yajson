import operator


def gen(root_peg):
    names = gen_names(count_em(root_peg))
    nameitems = (sorted(names.items(), key=operator.itemgetter(1))
                 + [(root_peg, 'root')])
    protos = '\n'.join(gen_prototype(name) for peg, name in nameitems)
    class Context:
        def gen(self, peg):
            if peg in names:
                return """c = %s (s, c);""" % names[peg]
            return peg.gen(self)
    context = Context()
    functions = '\n\n'.join(gen_function(context, peg, name)
                            for peg, name in nameitems)
    return '\n\n'.join([prelude, protos, functions, postlude])

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
  if (s->here == s->end) return EOF;
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
  return EOF;
}

static int expected_one_of (Scanner *s, const char *charset) {
  if (0 == s->failed) {
    PyErr_Format (ReadError, "At byte-offset %d, expected one of '%s'",
                  s->here - s->start, charset);
    fail (s);
  }
  return EOF;
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
  if (c != EOF) {
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

class Seq(Peg):
    def __init__(self, *pegs):
        self.pegs = map(parse, pegs)
    def __str__(self):
        return '(%s)' % ';'.join(map(str, self.pegs))
    def gen(self, context):
        return '\n'.join(map(context.gen, self.pegs))
    def has_null(self):
        return all(peg.has_null() for peg in self.pegs)
    def firsts(self):
        f = set()
        for peg in self.pegs:
            f |= peg.firsts()
            if not peg.has_null():
                break
        return f

class Literal(Peg):
    def __init__(self, c):
        assert 1 == len(c)
        self.c = c
    def __str__(self):
        return "'%s'" % self.c
    def gen(self, context):
        c_lit = c_literal_char(self.c)
        return ("""if (c != %s) expected (s, %s); c = advance (s);"""
                % (c_lit, c_lit))
    def has_null(self):
        return False
    def firsts(self):
        return set(self.c)

class StarSep(Peg):
    def __init__(self, peg, separator):
        self.peg = parse(peg)
        self.separator = parse(separator)
        assert not self.separator.has_null()
        self.pegs = (self.peg, self.separator)
    def __str__(self):
        return '(%s@%s)' % self.pegs
    def gen(self, context):
        return ("""\
for (;;) {
  %s
  if (!(%s)) break;
  %s
}""" % (indent(context.gen(self.peg)),
        gen_member_test(self.separator.firsts()),
        indent(context.gen(self.separator))))
    def has_null(self):
        return False
    def firsts(self):
        return Seq(self.peg, self.separator).firsts()

class OneOf(Peg):
    def __init__(self, *pegs):
        assert 0 < len(pegs)
        self.pegs = map(parse, pegs)
    def __str__(self):
        return '(%s)' % '|'.join(map(str, self.pegs))
    def gen(self, context):
        def gen_test(peg):
            if peg.has_null():
                return '1'
            return gen_member_test(peg.firsts())
        ok = '\nelse '.join("""\
if (%s) {
  %s
}""" % (gen_test(peg),
        indent(context.gen(peg)))
                            for peg in self.pegs)
        return """\
%s
else
  c = expected_one_of (s, "XXX");""" % ok  # XXX fill in with self.firsts()
    def has_null(self):
        return any(peg.has_null() for peg in self.pegs)
    def firsts(self):
        f = set()
        for peg in self.pegs:
            f |= peg.firsts()
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
}""" % (gen_member_test(self.peg.firsts()),
        indent(context.gen(self.peg))))
    def has_null(self):
        return True
    def firsts(self):
        return self.peg.firsts()

class Epsilon(Peg):
    def __str__(self):
        return '()'
    def gen(self, context):
        return ';'
    def has_null(self):
        return True
    def firsts(self):
        return set()

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

def gen_member_test(charset):
    if 0 == len(charset):
        return '0'
    else:
        # These checks may actually make it worse - CHECKME:
        if charset == set(' \t\r\n\f'):   # XXX right?
            return 'isspace (c)'
        if charset == set('0123456789'):
            return 'isdigit (c)'
        if charset == set('0123456789abcdefABCDEF'):
            return 'isxdigit (c)'
        tests = ["""c == %s""" % c_literal_char(c)
                 for c in sorted(charset)]
        return ' || '.join(tests)

def indent(string):
    return string.replace('\n', '\n  ')
