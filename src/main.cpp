#include <iostream>
#include <string>
#include "../../src/Functions/functions.h"
#include "../../src/PasswordClass/password.h"
#include <sqlite3.h>


using namespace std;

bool mainLoop(){
    bool running = true;
    while(running){
        cout<<"---------------------------"<<endl;
        cout<<"1. Insert New Password"<<endl;
        cout<<"2. Remove Password"<<endl;
        cout<<"3. Show List"<<endl;
        cout<<"4. Exit"<<endl;
        cout<<"---------------------------"<<endl;
        cout<<"Choose an option: ";
        int choice;
        cin>>choice;
        switch(choice){
            case 1:
                //Insert New Password
                int number;
                number = getnumber();
                if(number == 0){
                    running = false;
                    return running;
                }else if(number == -1){
                    while(number == -1){
                        number = getnumber();
                        if(number == 0){
                            running = false;
                            return running;
                        }
                    }
                }else{
                    string binary = decimalToBinary(number);
                    cout<<"Thats decimal rep for number "<<number<<" is: "<<binary<<endl;
                    int random = getRandomNumber(number) + number;
                    if(random > 50){
                        random = random - number;
                    }
                    string binaryRandom = decimalToBinary(random);
                    cout<<"Thats decimal rep for number "<<random<<" is: "<<binaryRandom<<endl;
                    
                    string password = getpassword();
                    cout<<"Password is: "<<password<<endl;
                    }
                break;
            case 2:
                //Remove Password
                break;
            case 3:
                //Show List
                break;
            case 4:
                running = false;
                return running;
            default:
                cout<<"Invalid option. Please try again."<<endl;
        }
    }
    return running;
}


void createTable(sqlite3* db) {
    const char* create_table_sql =
        "CREATE TABLE IF NOT EXISTS Records ("
        "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
        "Password TEXT NOT NULL, "
        "Decimal TEXT NOT NULL);";

    char* errMsg;
    if (sqlite3_exec(db, create_table_sql, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        cerr << "Failed to create table: " << errMsg <<  endl;
        sqlite3_free(errMsg);
    }
}

#include <iostream>
#include <sqlite3.h>

void insertUser(sqlite3* db, const  string& name, const  string& email) {
    string sql = "INSERT INTO Records (Password, Decimal) VALUES (?, ?);";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        //input ta strings anakatemena!
        sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, email.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            cerr << "Failed to insert data: " << sqlite3_errmsg(db) <<  endl;
        } else {
            cout << "Data inserted successfully!" <<  endl;
        }

        sqlite3_finalize(stmt);
    } else {
        cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) <<  endl;
    }
}


// int main(){
//     //Reading number!
//     int n = getnumber();
//     string res = decimalToBinary(n);
//     cout<<"Thats decimal rep for number "<<n<<" is: "<<res<<endl;
//     //Shuffle the number!
//     int random = getRandomNumber(n) + n;
//     if(random > 50){
//         random = random - n;
//     }
//     string res1 = decimalToBinary(random);
//     cout<<"Thats decimal rep for number "<<random<<" is: "<<res1<<endl;
    

//     string password = getpassword();
//     cout<<"Password is: "<<password<<endl;

//     sqlite3* DB;
//     int exit = sqlite3_open("mydatabase.db", &DB);

//     if (exit) {
//         cerr << "Error opening DB: " << sqlite3_errmsg(DB) <<  endl;
//         return -1;
//     } else {
//         createTable(DB);
//         insertUser(DB, password, res1);
//         cout << "Opened database successfully!" <<  endl;
//     }


//     sqlite3_close(DB);

//     return 0;
//     // return -1;
// }

int main(){
    mainLoop();
    return 0;
}