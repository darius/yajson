from peg import Recur, Star, OneOf, Seq, Maybe, StarSep, gen
from peg import Variable, Scope, Code


normal_chars = set(chr(i) for i in range(32, 256))
normal_chars.remove('"')
normal_chars.remove('\\')
normal_chars.remove(chr(127))      # I think this counts as a control character
normal_chars = list(sorted(normal_chars))

result = Variable('result', 'PyObject*', 'NULL')

value   = Recur(False, '{["-0123456789tfn', [result])

w       = Star(OneOf(*' \t\r\n\f'))   # XXX right?

digit   = OneOf(*'0123456789')
digits  = Seq(digit, Star(digit))
number  = Seq(Maybe('-'),
              OneOf('0', Seq('123456789', Star(digit))),
              Maybe(Seq('.', digits)),
              Maybe(Seq('eE', Maybe('+-'), digits)))

hexdig  = OneOf(*'0123456789abcdefABCDEF')
escseq  = OneOf('"\\/bfnrt', Seq('u', hexdig, hexdig, hexdig, hexdig))
ch      = OneOf(*(normal_chars + [Seq('\\', escseq)]))
jstring = Seq('"', Star(ch), '"')

jarray  = Seq('[', w, Maybe(StarSep(Seq(value, w), Seq(',', w))), ']')

jobject = Seq('{', w, Maybe(StarSep(Seq(jstring, w, ':', w, value, w), 
                                    Seq(',', w))),
              '}')

jvalue  = Scope([result],
                OneOf(jobject, jarray, jstring, number,
                      Seq(Seq(*'true'),
                          Code('result = Py_True; Py_INCREF (result);')),
                      Seq(Seq(*'false'),
                          Code('result = Py_False; Py_INCREF (result);')),
                      Seq(Seq(*'null'),
                          Code('result = Py_None; Py_INCREF (result);'))))


def main():
    print gen(jvalue)

if __name__ == '__main__':
    main()
