from peg import Recur, Star, OneOf, Seq, Maybe, StarSep, NormalChar, gen


value   = Recur(False, '{["-0123456789tfn')

w       = Star(OneOf(*' \t\r\n\f'))   # XXX right?

digit   = OneOf(*'0123456789')
digits  = Seq(digit, Star(digit))
number  = Seq(Maybe('-'),
              OneOf('0', Seq('123456789', Star(digit))),
              Maybe(Seq('.', digits)),
              Maybe(Seq('eE', Maybe('+-'), digits)))

hexdig  = OneOf(*'0123456789abcdefABCDEF')
escseq  = OneOf('"\\/bfnrt', Seq('u', hexdig, hexdig, hexdig, hexdig))
ch      = OneOf(NormalChar(), Seq('\\', escseq))
jstring = Seq('"', Star(ch), '"')

jarray  = Seq('[', w, Maybe(StarSep(Seq(value, w), Seq(',', w))), ']')

jobject = Seq('{', w, Maybe(StarSep(Seq(jstring, w, ':', w, value, w), 
                                    Seq(',', w))),
              '}')

jvalue  = OneOf(jobject, jarray, jstring, number,
                Seq(*'true'), Seq(*'false'), Seq(*'null'))


def main():
    print gen(jvalue)

if __name__ == '__main__':
    main()
