#include <iostream>
#include <string>
#include "../../src/Functions/functions.h"
#include "../../src/PasswordClass/password.h"
#include <sqlite3.h>


using namespace std;

void createTable(sqlite3* db) {
    const char* create_table_sql =
        "CREATE TABLE IF NOT EXISTS Records ("
        "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
        "Password TEXT NOT NULL, "
        "Decimal TEXT NOT NULL);";

    char* errMsg;
    if (sqlite3_exec(db, create_table_sql, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "Failed to create table: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    }
}

#include <iostream>
#include <sqlite3.h>

void insertUser(sqlite3* db, const std::string& name, const std::string& email) {
    std::string sql = "INSERT INTO Records (Password, Decimal) VALUES (?, ?);";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        // Δέσε τα strings στις θέσεις 1 και 2 (?)
        sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, email.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Failed to insert data: " << sqlite3_errmsg(db) << std::endl;
        } else {
            std::cout << "Data inserted successfully!" << std::endl;
        }

        sqlite3_finalize(stmt);
    } else {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
    }
}


int main(){
    //Reading number!
    int n = getnumber();
    string res = decimalToBinary(n);
    cout<<"Thats decimal rep for number "<<n<<" is: "<<res<<endl;
    //Shuffle the number!
    int random = getRandomNumber(n) + n;
    if(random > 50){
        random = random - n;
    }
    string res1 = decimalToBinary(random);
    cout<<"Thats decimal rep for number "<<random<<" is: "<<res1<<endl;
    

    string password = getpassword();
    cout<<"Password is: "<<password<<endl;

    for(int i=0; i<6; i++){
        if(res1[i] == '1'){
            cout<<"We do 1 shift!"<<endl;
        }
        else{
            cout<<"We do 0 shift!"<<endl;
        }
    }

    sqlite3* DB;
    int exit = sqlite3_open("mydatabase.db", &DB);

    if (exit) {
        std::cerr << "Error opening DB: " << sqlite3_errmsg(DB) << std::endl;
        return -1;
    } else {

        createTable(DB);
        insertUser(DB, password, res1);
        std::cout << "Opened database successfully!" << std::endl;
    }


    sqlite3_close(DB);

    return 0;
    // return -1;
}

