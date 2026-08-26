BOFNAME := clipboardinject
ARMORYNAME := clipboard
COMINCLUDE := -I ../../common
LIBINCLUDE := -l user32
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
CC := x86_64-w64-mingw32-clang

all:
	$(CC_x64) -o $(BOFNAME).x64.o $(COMINCLUDE) -Os -c entry.c -DBOF 
	$(CC_x86) -o $(BOFNAME).x86.o $(COMINCLUDE) -Os -c entry.c -DBOF
	mkdir -p ../../../Injection/$(BOFNAME) ../../../Injection/$(ARMORYNAME)
	cp $(BOFNAME).x64.o ../../../Injection/$(BOFNAME)/$(BOFNAME).x64.o
	cp $(BOFNAME).x86.o ../../../Injection/$(BOFNAME)/$(BOFNAME).x86.o
	mv $(BOFNAME).x64.o ../../../Injection/$(ARMORYNAME)/$(ARMORYNAME).x64.o
	mv $(BOFNAME).x86.o ../../../Injection/$(ARMORYNAME)/$(ARMORYNAME).x86.o

test:
	$(CC_x64) entry.c -g $(COMINCLUDE) $(LIBINCLUDE) -o $(BOFNAME).x64.exe
	$(CC_x86) entry.c -g $(COMINCLUDE) $(LIBINCLUDE) -o $(BOFNAME).x86.exe

scanbuild:
	$(CC) entry.c -o $(BOFNAME).scanbuild.exe $(COMINCLUDE) $(LIBINCLUDE)

check:
	cppcheck --enable=all --suppress=missingIncludeSystem --suppress=unusedFunction --suppress=unusedStructMember $(COMINCLUDE) --platform=win64 entry.c

clean:
	rm $(BOFNAME).*.exe
