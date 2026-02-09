#include <iostream>
#include <string>
#include "../../src/Functions/functions.h"
#include "../../src/PasswordClass/password.h"
#include <sqlite3.h>
#include <vector>
#include <algorithm>




using namespace std;


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


void insertUser(sqlite3* db, const  string& key, const  string& pass) {
    string sql = "INSERT INTO Records (Password, Decimal) VALUES (?, ?);";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        //input ta strings anakatemena!
        sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, pass.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            cerr << "Failed to insert data: " << sqlite3_errmsg(db) <<  endl;
        }
        sqlite3_finalize(stmt);
    } else {
        cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) <<  endl;
    }
}

void RemoveUser(sqlite3* db, vector<Password>& vectorPass, Password& p) {
    // 1. Διαγραφή από τη βάση
    string sql = "DELETE FROM Records WHERE Password = ?;";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, p.getPass().c_str(), -1, SQLITE_TRANSIENT);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            cerr << "Failed to delete user: " << sqlite3_errmsg(db) << endl;
        }
        sqlite3_finalize(stmt);
        cout<<p.getPass()<<" Removed"<<endl;
    } else {
        cerr << "Failed to prepare DELETE: " << sqlite3_errmsg(db) << endl;
    }


    for (vector<Password>::iterator it = vectorPass.begin(); it != vectorPass.end(); it++){
        if(it->getPass() == p.getPass()){ 
         it = vectorPass.erase(it);
         if(vectorPass.size() == 0){
            cout<<"Database is empty now!\n";
            break;
         }
        }else ++it;
    }

}


void loadUsers(sqlite3* db, vector<Password>& vectorPass) {
    string sql = "SELECT Password, Decimal FROM Records;";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char* passwordText = sqlite3_column_text(stmt, 0);
            const unsigned char* keyText = sqlite3_column_text(stmt, 1);

            if(passwordText && keyText) {
                string passStr = reinterpret_cast<const char*>(passwordText);
                string keyStr = reinterpret_cast<const char*>(keyText);

                vectorPass.emplace_back(passStr, keyStr); // assuming Password has constructor Password(string, string)
            }
        }
        sqlite3_finalize(stmt);
    } else {
        cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << endl;
    }
}

void clearTable(sqlite3* db) {
    const char* sql = "DELETE FROM Records;";
    char* errMsg = nullptr;

    if (sqlite3_exec(db, sql, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        cerr << "Failed to clear table: " << errMsg << endl;
        sqlite3_free(errMsg);
    }
}


bool mainLoop(vector<Password>& vectorPass, sqlite3* db){
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

                    Password p(binaryRandom, password);
                    vectorPass.push_back(p);
                    cout<<"Password and Key stored successfully!"<<endl;
                    }
                break;
            case 2:{
                //Remove Password
                string user;
                cout<<"Input the password that you want to remove:";
                cin>>user;
                for(auto& p : vectorPass){
                    if(p.getPass() == user){
                        RemoveUser(db, vectorPass, p);
                    }
                }
                break;
            }
            case 3:
                if(vectorPass.size() == 0){
                    cout<<"Database is empty :(\n";
                }
                for(const auto& p : vectorPass){
                    p.display();
                }
                int option;
                cout<<"To continue press 1: ";
                cin>>option;
                if(option){
                    break;
                }else{
                    running = false;
                    return running;
                }
                break;
            case 4:
                running = false;
                return running;
            default:
                cout<<"Invalid option. Please try again."<<endl;
                return running;
        }
    }
    return running;
}

int main(){
    //Open database
    sqlite3* DB;
    int exit = sqlite3_open("database.db", &DB);

    //Initialize Vector that stores passwords and run main loop
    vector<Password> vectorPass;
    if(!exit){
        loadUsers(DB, vectorPass);
    }
    mainLoop(vectorPass, DB);

    //Check if database exists
    clearTable(DB);
    if (exit) {
        cerr << "Error opening DB: " << sqlite3_errmsg(DB) <<  endl;
        return -1;
    } else {
        createTable(DB);
        for(const auto& p : vectorPass){
            insertUser(DB, p.getKey(), p.getPass());
        }
        cout << "Database updated successfully!" <<  endl;
    }


    sqlite3_close(DB);
    return 0;
}