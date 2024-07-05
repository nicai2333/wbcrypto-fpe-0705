#!/bin/bash
rm -rf bin/*

javac -cp lib/mysql-connector-java-8.0.16.jar -d bin src/DatabaseManager.java 

java -cp ./lib/mysql-connector-java-8.0.16.jar:./bin DatabaseManager