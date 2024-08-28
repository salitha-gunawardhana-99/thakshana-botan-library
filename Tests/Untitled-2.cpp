#include <iostream>

class Person {
public:
    Person(const std::string &name, int age) : name(name), age(age) {}

    void introduce() const {
        std::cout << "Hello, my name is " << name << " and I am " << age << " years old." << std::endl;
    }

private:
    std::string name;
    int age;
};

int main() {
    Person person("Alice", 30);
    person.introduce();
    return 0;
}
