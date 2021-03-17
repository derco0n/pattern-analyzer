/*
This programm will analyze a list of passwords (one per line) for patterns,
which can be used during further bruteforce-attempts using tools like hashcat.

Dennis Marx (derco0n), 03/2021

compile with: g++ ./main.cpp ./lib/analyzer.cpp -o ./pattern-analyze
*/

#include <stdlib.h>
#include <strings.h>
#include <iostream>
#include "lib/analyzer.h"

using namespace std;

static inline bool test_file_exists (const std::string& name) { //Test if a file exists
    if (FILE *file = fopen(name.c_str(), "r")) {
        fclose(file); //Close the file if it had been opened
        return true;
    } else {
        return false;
    }   
}

static void printHelp(char *bin){
    cout << "Know the people, know the words..." << endl;    
    cout << "This tool will aid you in finding patterns (to be used for bruteforcing with hashcat) from a list of passwords." << endl;
    cout << "This is free software and comes without any warranty." << endl;
    cout << "This program is inteded for legal use only. Never use it without explicit permission." << endl;
    cout << "Written by derco0n (https://github.com/derco0n)" << endl;
    cout << endl;
    cout << "Usage:" << endl;
    cout << "######" << endl;
    cout << endl;
    cout << bin << " <inputfile> <outputfile>" << endl;
    cout << endl;
    cout << "inputfile\ta file containing a list of passwords (one per line)" << endl;
    cout << "outputfile\ta file to which the patterns should be written..." << endl;
    cout << endl;
}

int main (int argc, char *argv[]) {
    
    if (argc != 3) {
        printHelp(argv[0]);
        return 1;
    }

    if (!test_file_exists(argv[1])){ //Test if the inputfile exists
        cout << "The specified input file \"" << argv[1] << "\" could not be found!" << endl;
        return 2;
    }
    else {
        cout << "found \"" << argv[1] << "\"" << endl;
    }

    if (test_file_exists(argv[2])){ //Test if the outputfile already exists
        cout << "The specified output file \"" << argv[2] << "\" already exists. Aborting!" << endl;
        return 3;
    }

    //Open Input and output files
    FILE *infile = fopen(argv[1], "r");    
    cout << "Opened input-file \"" << argv[1] << "\"" << endl; //DEBUG

    FILE *outfile;
    if (!(outfile = fopen(argv[2], "w"))){   
        //Error opening output file for writing
        cout << "Unable to write to output-file \"" << argv[2] << "\". Aborting!" << endl;
        return 4;

    }
    cout << "Opened output-file \"" << argv[2] << "\"" << endl; //DEBUG

    int a=0;
    int b=1;

    analyzer * myanalyzer = new analyzer(infile, outfile);
    
    myanalyzer->parse(); //DEBUG

    fclose(outfile); 
    fclose(infile);
 
 
    return 0;  //Normal exit
}