#include "analyzer.h"

//Constructor
analyzer::analyzer(FILE *infile, FILE *outfile) {
    this->_infile=infile;
    this->_outfile=outfile;
}

std::string analyzer::chartopattern(char c) {
    /*
    Returns a pattern for a given char.
    
    From https://hashcat.net/wiki/doku.php?id=mask_attack :

    ?l = abcdefghijklmnopqrstuvwxyz
    ?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ
    ?d = 0123456789    
    ?s = «space»!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
    
    */
   if (c>0x60 && c < 0x7b){
       //lowercase letter
       return std::string("?l");
   }

   if (c>0x40 && c < 0x5b){
       //uppercase letter
       return std::string("?u");
   }

   if (c>0x2f && c < 0x3a){
       //decimal number
       return std::string("?d");
   }

   if (c != '\r' && c != '\n') {
       //not a linebreak but everything else
        return std::string("?s"); //assuming special char      
   }

   //default
   return std::string("");
}

std::string analyzer::findpattern(char * txt, int len){
    std::string myreturn = std::string("");

    for (int i=0;i<=len;i++){
        char c = txt[i];
        if (c==0x00) { 
            break; //Abort if we hit the end of the string (NULL-BYTE)
        }
        myreturn = myreturn + this->chartopattern(c);
        //std::cout << this->chartopattern(c); //DEBUG
    }
    myreturn = myreturn + "\r\n";
    
    return myreturn;
}

void analyzer::parse(void) {
    // Parses the input file for patterns    
    std::vector<pw_pattern> patterns;  //a vector that will contain the patterns we found (basically an arraylist)
    

    char buf[255];    
    while(fgets (buf, sizeof(buf), this->_infile)) {
        
        std::string pat = this->findpattern(buf, sizeof(buf));

        if (pat.compare("")!=0) { //If the pattern is not ""

            bool pattern_found=false;
            //iterate through all patterns we've got so far...
            for (pw_pattern& p: patterns){ //... by non-const reference pointer (basically a foreach with write-access)
                if (p.pattern.compare(pat)==0){
                    //pattern found. it therefore already exists
                    p.count=p.count+1; //increment the occurance-counter by one
                    pattern_found=true;
                    break;
                }
            }
            if (!pattern_found){
                //Pattern was not found in our vector-list
                // Create a new pattern...
                pw_pattern new_pattern;
                new_pattern.pattern=pat;
                new_pattern.count=1;

                //And add it to the list
                patterns.push_back(new_pattern);
            }
        
        }
    }

    //Sort the vector-table by count-field to order it by occurances
    std::sort (patterns.begin(), patterns.end(),[](const pw_pattern& pl, const pw_pattern& ph) 
        {
            //return pl.count < ph.count; //Order ascending
            return pl.count > ph.count; //Order descending
        }
   );

        
    std::cout << "occurance;pattern" << std::endl;
    std::cout << "#################" << std::endl;
    //Iterate through all patterns again...
    for (pw_pattern& p: patterns){ //... by reference pointer (basically a foreach with write-access)
        // ... and output the results
        std::cout << p.toString();
        fputs(p.toString().c_str(), this->_outfile);
    }



}

