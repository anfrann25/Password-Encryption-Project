# Compiler
CXX = g++

# Flags
CXXFLAGS = -Wall -std=c++17 -I./src/Functions -I./src/PasswordClass
LDFLAGS = -lsqlite3



# Sources
SRC = \
	src/Functions/functions.cpp \
	src/PasswordClass/password.cpp \
	src/main.cpp

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
