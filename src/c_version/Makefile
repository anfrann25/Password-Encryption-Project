# Compiler
CXX = g++

# Flags
CXXFLAGS = -Wall -std=c++17 -I ./Functions -I ./PasswordClass
LDFLAGS = -lsqlite3



# Sources
SRC = \
	./Functions/functions.cpp \
	./PasswordClass/password.cpp \
	main.cpp

# Object files
OBJ = $(SRC:.cpp=.o)

# Output executable
TARGET = main

# Default rule
all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(OBJ) -o $@ $(LDFLAGS)

# Clean rule
clean:
	rm -f $(OBJ) $(TARGET)

del:
	rm -f database.db
