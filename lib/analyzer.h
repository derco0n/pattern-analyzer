#pragma once 
#include <strings.h> //strings
#include <iostream> //cout, cin
#include <stdlib.h>
#include <vector> //Vector
#include <algorithm> //Sort

class analyzer {
    private:        

    protected:
    FILE * _infile, * _outfile;    

    // Used to define and count a pattern
    struct pw_pattern {        
        uint count;
        std::string pattern;
        std::string type;
        uint64_t combinations;
        std::string toString(void){
            return std::to_string(count) + ";" + type + ";" + std::to_string(combinations) + ";" + pattern;
            }
    };

    std::string findpattern(char * txt, int len, int mode); //Finds a bruteforce-pattern for a given string

    std::string chartopattern(char c, int mode); //returns a pattern for a given char

    uint64_t patterntocombinations(std::string pattern);  //calculates possible combinations for a given pattern    

    public:
    static const std::string versioninfo;

    //Contructor
    analyzer(FILE *infile, FILE *outfile);

    void parse(void);

};
