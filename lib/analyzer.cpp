#include "analyzer.h"

const std::string analyzer::versioninfo="0.21";

//Constructor
analyzer::analyzer(FILE *infile, FILE *outfile) {
    this->_infile=infile;
    this->_outfile=outfile;
}

std::string analyzer::chartopattern(char c, int mode=0) {
    /*
    Returns a pattern for a given char.
    
    From https://hashcat.net/wiki/doku.php?id=mask_attack :

    ?l = abcdefghijklmnopqrstuvwxyz
    ?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ
    ?d = 0123456789    
    ?s = «space»!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
    ?h = 0123456789abcdef
    ?H = 0123456789ABCDEF
    
    */
   if (mode == 1){       
       //Need to find alternative pattern
        if ((c>0x2f && c < 0x3a) || (c>0x60 && c < 0x67)){
           //0123456789abcdef
           return std::string("?h");
        }
        if ((c>0x2f && c < 0x3a) || (c>0x40 && c < 0x47)){
           //0123456789ABCDEF
           return std::string("?H");
        }

        //char is not found in alternative pattern (as it is probably something beyond f/F). we need to recall outself here in default mode...
        return chartopattern(c, 0); //run "my other self" again in default mode
   }

   /*
   else if (mode == 2)
   {
       if (
           (c>0x60 && c < 0x7b) || 
           (c>0x40 && c < 0x5b) ||
           (c>0x2f && c < 0x3a) ||
           (c != '\r' && c != '\n')
           )
           {
               return std::string("?a");
           }
   }
   */

   else { //mode is 0   
        
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
   }

   //default
   return std::string("");
}

std::string analyzer::findpattern(char * txt, int len, int mode){
    std::string myreturn = std::string("");

    for (int i=0;i<=len;i++){
        char c = txt[i];
        if (c==0x00) { 
            break; //Abort if we hit the end of the string (NULL-BYTE)
        }
        myreturn = myreturn + this->chartopattern(c, mode);
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
        
        int modes[]= {0, 1};  //specify the pattern searchmodes (0 default, 1 alternative pattern)

        //Get a pattern for each mode
        for (const int& m: modes){  //foreach with const reference (read-only)
            //std::cout << "searching pattern for \"" << buf << "\" with mode " << m;  //DEBUG

            std::string pat = this->findpattern(buf, sizeof(buf), m);

            //std::cout << " => " << pat << std::endl; //DEBUG

            if (pat.compare("")!=0) { //If the pattern is not ""

                bool pattern_found=false;
                //iterate through all patterns we've got so far...
                for (pw_pattern& p: patterns){ //... by non-const reference pointer (basically a foreach with write-access)
                    if (p.pattern.compare(pat)==0)
                    {
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
                    if (m==0){
                        new_pattern.type="default";
                    }
                    else {
                        new_pattern.type="alternative";
                    }

                    //And add it to the list
                    patterns.push_back(new_pattern);
                }
            
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

        
    std::cout << "occurance;patterntype;pattern" << std::endl;
    std::cout << "#############################" << std::endl;
    //Iterate through all patterns again...
    for (pw_pattern& p: patterns){ //... by reference pointer (basically a foreach with write-access)
        // ... and output the results
        std::cout << p.toString();
        fputs(p.toString().c_str(), this->_outfile);
    }



}

