#include <iostream>
#include <string>

using namespace std;

class Password{
    private:
        string key;
        string pass;
    public:
        Password(string k, string p): key(k), pass(p) {}
        string getKey() const { return key; }
        string getPass() const { return pass; }
        void setKey(const string& k) { key = k; }
        void setPass(const string& p) { pass = p; }
        void display() const {
            cout << "Key: " << key << ", Password: " << pass << endl;
        }
};