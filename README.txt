javac -XDignore.symbol.file Client.java
javac -XDignore.symbol.file KDC.java
 
We need to compile Client and KDC files with the -XDignore.symbol.file as shown above. Other ones can be compiled directly.

javac MailServer.java
javac DatabaseServer.java
javac WebServer.java

Client should use the last password logged in KDC_Log.txt to be able to be verified.