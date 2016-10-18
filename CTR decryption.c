#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <fstream>
#include <vector>
#include <string>
#include <iostream>
#include <bitset>

#define PORTNO 33333
//#define PORTNO 33334
#define HOSTNAME "burrow.soic.indiana.edu"
#define BLOCKSIZE 128
#define CIPHERTEXT_FILENAME "/ctr-ciphertext"

#define SUCCESS 0
#define ERROR -1
#define INVALID_PADDING 1

using namespace std;

void error(const char *msg)
{
    perror(msg);
    exit(0);
}

char* ServerClient(vector <char> ctbuffer, int ctlength);

int main(int argc, char **argv)
{
    char *response = (char*)malloc(7*sizeof(char));
      // open ciphertext
    ifstream ctstream(CIPHERTEXT_FILENAME, ios::binary);
    if (ctstream.fail())
    {
        error("ERROR: failed to open ciphertext");
    }
    ctstream.seekg(0, ios::end);
    streamsize ctlength = ctstream.tellg();
    ctstream.seekg(0, ios::beg);
    vector<char> ctbuffer(ctlength);
    vector<char> plaintext;
	int x;
    for (int y = 0; argv[1][y] != '\0'; ++y)
    {    
      
      if(argv[1][y] >= '0' && argv[1][y] <= '9')
      {
        x = x*10 + argv[1][y] - '0';
      }
    }
  
    int blockSize = 16 * x;
    
    if (!ctstream.read(ctbuffer.data(), ctlength))
    {
        error("ERROR: failed to read ciphertext");
    }
    int j,k = 1,i = 1;
    if ( x == 0 )
    {
           std::bitset<8> padding(std::string(std::bitset<8>(10).to_string()));
           std::bitset<8> WantedPadding(std::string(std::bitset<8>(11).to_string()));
           std::bitset<8> Plaintextbits(std::string(std::bitset<8>(0).to_string()));
           int a=1,b = 11;
            std::bitset<8> Temp;
           for (int i=1; i <= 5; i++)
           {
                    for (a=1; a<=b; a++)
                       {
                     	        std::bitset<8> byte1(ctbuffer.at(ctlength-a));
                                Temp = byte1 ^ padding;
                                Temp = Temp ^ WantedPadding;
                                long subs1 = Temp.to_ulong();
                                ctbuffer.at(ctlength-a) = static_cast<char>(subs1);
               
                        }
            
                    std::bitset<8> byte(ctbuffer.at(ctlength-a));
                   
                    for (int n = 1; n <= 255; n++)
                    { 

               		 std::bitset<8> binary = std::bitset<8>(n);
             		 Temp = byte ^ binary;
              		  long subs = Temp.to_ulong();
              		  ctbuffer.at(ctlength-a) = static_cast<char>(subs);
           	         response = ServerClient(ctbuffer, ctlength);
                         if(!strcmp(response, "SUCCESS"))
                          {
                          
                             Plaintextbits = binary ^ WantedPadding;
                             long push = Plaintextbits.to_ulong();
                             plaintext.push_back(static_cast<char>(push));
            	             padding = WantedPadding;
                             b++;
                	     WantedPadding = std::bitset<8>(b);
                             break;
                           }
                          if (n==255) break;
                        }
                

             }
        for (int q = plaintext.size()-1; q >= 0; q--)
         {
            cout << plaintext.at(q);
         }
      return 0;
    }
    ctlength = ctlength - blockSize;
    ctbuffer.resize(ctlength); 
      
     std::bitset<8> padding(std::string(std::bitset<8>(0).to_string()));
     std::bitset<8> WantedPadding(std::string(std::bitset<8>(0).to_string()));
     std::bitset<8> Plaintextbits(std::string(std::bitset<8>(0).to_string()));
     int a=1,b = 1;
     for (i=1; i <= 16; i++)
     {
      std::bitset<8> byte(ctbuffer.at(ctlength-b));
      std::bitset<8> Temp;
      for (int n = 1; n <= 255; n++)
      {
         std::bitset<8> binary = std::bitset<8>(n);
        Temp = byte ^ binary;
	 long subs = Temp.to_ulong();
          ctbuffer.at(ctlength-a) = static_cast<char>(subs);
  	response = ServerClient(ctbuffer, ctlength);
        if(!strcmp(response, "SUCCESS"))
    {
        Plaintextbits = binary ^ WantedPadding;
      long push = Plaintextbits.to_ulong();
     plaintext.push_back(static_cast<char>(push));
      padding = WantedPadding;
     WantedPadding = std::bitset<8>(b);
                    for (a=1; a<=b; a++)
                    {
                         std::bitset<8> byte1(ctbuffer.at(ctlength-a));
                         Temp = byte1 ^ padding;
                         Temp = Temp ^ WantedPadding;
                         long subs1 = Temp.to_ulong();
                         ctbuffer.at(ctlength-a) = static_cast<char>(subs1);
                    }
                    break;
                }
                if (n==255) break; 
      } 
      b++;
      
    } 
    for (int q = plaintext.size()-1; q >= 0; q--)
    {  
       cout << plaintext.at(q);
    }
    return 0;
}

char* ServerClient(vector <char> ctbuffer, int ctlength)
{
    int sockfd, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    char *response = (char*)malloc(7*sizeof(char));

    
    // open socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
    if (sockfd < 0)
    {
        error("ERROR: failed to open socket");
    }

    // connect to host
    server = gethostbyname(HOSTNAME);
    if (server == NULL)
    {
        error("ERROR: no such host");
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *) server->h_addr, (char *) &serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(PORTNO);
    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    {
        error("ERROR: failed to connect");
    }

    // transmit ciphertext
    n = write(sockfd, ctbuffer.data(), ctlength);
    if (n < 0)
    {
         error("ERROR: writing to socket failed");
    }

    // get response
    n = read(sockfd, response, 7);
    if (n < 0)
    {
         error("ERROR: reading from socket failed");
    }
    return response;
    // cleanup
    close(sockfd);
    
    
}
