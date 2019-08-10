# Data_Splitting_TPE
Data splitting system

Python 3.5.8

This project was created for highschool project
My project's goal is to create a secure transfer system using data splitting concept

The system operation is kinda complex but to summarize there is 4 phases :

Phase 1 : connexion phase

  Client 1 connect to Server 1
  Client 1 connect to Server 2
  Client 2 connect to Server 2
  Client 2 connect to Server 1
  
Phase 2 : Creation of temporary encryption keys using DH algorithm

  each pair of Client/Server and Client/Client will create a encryption key together that'll useful for the next phase
  
Phase 3 : Creation of real encryption keys

  Each Client will create a large bloc of Key and a large bloc of Nonce for each targer (server 1, server 2, client x)
  Bloc of key/nonce avoid sending keys often and prevent an attacker from recovering it
  
Phase 4 : Sending/Receiving the file

  Client 1 will choose a file, process it (it'll too complicated to describe it but if you want to know more, i let you read the code),
  and send a part of file to Server1 and Server2, they process it too and send it to Client 2 which will process each part,
  put them together, and process the whole file in order to save it in the system, and it repeat the process for Client 2.
  
  
