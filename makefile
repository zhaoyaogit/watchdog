# LINUX version
.SUFFIXES:
.SUFFIXES: .cpp .obj .o

CPP = g++ -m64

PUB_INC = -I./

INC_DIR = $(PUB_INC)
LIB_DIR = -L./
CPPDEFS =  -fPIC -DUNIX -DLINUX -D_MT -DNDEBUG -DTHREAD_SAFE -Wall -std=c++11

.cpp.o:
	$(CPP) -c  $(CPPDEFS) $(INC_DIR)  $< -o $@  -g

OBJ = watchdog.o inifile.o stdafx.o

all : watchdog.lexe clean

watchdog.lexe:$(OBJ)
	$(CPP) -w -g -O2 -o $@ $(LIB_DIR) $(CPPDEFS) $(OBJ) -g 
	#mv watchdog.lexe 
clean:
	rm *.o