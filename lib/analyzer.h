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
        std::string toString(void){
            return std::to_string(count) + ";" + pattern;
            }
    };

    std::string findpattern(char * txt, int len); //Finds a bruteforce-pattern for a given string

    std::string chartopattern(char c); //returns a pattern for a given char

    public:
    //Contructor
    analyzer(FILE *infile, FILE *outfile);

    void parse(void);

};
