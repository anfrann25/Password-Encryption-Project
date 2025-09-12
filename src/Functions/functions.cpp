#include "functions.h"

#include <iostream>
#include <string>
#include <bitset>
#include <cstdlib>   // για rand() και srand()
#include <ctime>     // για time()


using namespace std;

int getnumber(){
    int input;
    cout<<"Give a number 1-50: ";
    cin>>input;
    if(input<1 || input>50){
        cout<<"Error: number out of range (1–50)"<<endl;
        return -1;
    }
    return input;
}


string decimalToBinary(int number) {
    if (number < 1 || number > 50) {
        return "Error: number out of range (1–50)";
    }
    return bitset<6>(number).to_string();
}



int getRandomNumber(int max){
    if (max < 0) {
        return -1; // ή χειρίσου το όπως θες
    }

    // Αρχικοποίηση του seed (να γίνεται μόνο μία φορά στο πρόγραμμα!)
    static bool seeded = false;
    if (!seeded) {
         srand(static_cast<unsigned int>( time(nullptr)));
        seeded = true;
    }

    return  rand() % (max + 1);  // από 0 έως max
}

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