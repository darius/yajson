all: yajson.so

test:
	python testme.py
	python checkme.py

yajson.c: peg.py genjson.py
	python genjson.py >yajson.c

yajson.so: buildyajson.py yajson.c
	python buildyajson.py build
	cp build/lib.*/yajson.so .

clean:
	rm -rf build
	rm -f *~ *.pyc yajson.so
