#include "functions.h"
#include <iostream>
#include <string>
#include <bitset>
#include <cstdlib>  
#include <ctime>    


using namespace std;

//Function that takes input an number.
int getnumber(){
    int input;
    cout<<"Give a number 1-50, if u want to exit give 0:";
    cin>>input;
    if(input == 0){
        return 0;
    }
    if(input<1 || input>50){
        cout<<"Error: number out of range (1–50)"<<endl;
        return -1;
    }
    return input;
}

//Function that returns the binary of an int number.
string decimalToBinary(int number) {
    if (number < 1 || number > 50) {
        return "Error: number out of range (1–50)";
    }
    return bitset<6>(number).to_string();
}


//Function that returns a random number.
int getRandomNumber(int max){
    if (max < 0) {
        return -1;
    }

    static bool seeded = false;
    if (!seeded) {
         srand(static_cast<unsigned int>( time(nullptr)));
        seeded = true;
    }

    return  rand() % (max + 1);  // από 0 έως max
}

//Function that takes input and return it.
string getpassword(){
    string pass;
    cout<<"Give a password: ";
    cin>>pass;
    return pass;
}



// int main(){
//     string name = getname();
//     cout<<name;
//     return -1;
// }