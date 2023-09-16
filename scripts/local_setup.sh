#!/usr/bin/env bash

mvn org.apache.maven.plugins:maven-install-plugin:3.1.1:install-file -Dfile=libs/commons-core-automation.jar -DgroupId=com.snc -DartifactId=commons-core-automation -Dversion=19.0.0.0 -Dpackaging=jar -DlocalRepositoryPath=$HOME/.m2/repository
mvn org.apache.maven.plugins:maven-install-plugin:3.1.1:install-file -Dfile=libs/snc-automation-api.jar -DgroupId=com.snc -DartifactId=snc-automation-api -Dversion=19.0.0.0 -Dpackaging=jar -DlocalRepositoryPath=$HOME/.m2/repository
mvn org.apache.maven.plugins:maven-install-plugin:3.1.1:install-file  -Dfile=libs/commons-glide.jar -DgroupId=com.snc -DartifactId=commons-glide -Dversion=19.0.0.0 -Dpackaging=jar -DlocalRepositoryPath=$HOME/.m2/repository
mvn org.apache.maven.plugins:maven-install-plugin:3.1.1:install-file  -Dfile=libs/gson.jar -DgroupId=com.google.code.gson -DartifactId=gson -Dversion=2.8.2 -Dpackaging=jar -DlocalRepositoryPath=$HOME/.m2/repository
mvn org.apache.maven.plugins:maven-install-plugin:3.1.1:install-file  -Dfile=libs/guava.jar -DgroupId=com.google.guava -DartifactId=guava -Dversion=2.8.2 -Dpackaging=jar -DlocalRepositoryPath=$HOME/.m2/repository
mvn org.apache.maven.plugins:maven-install-plugin:3.1.1:install-file  -Dfile=libs/mid.jar -DgroupId=com.snc -DartifactId=mid -Dversion=19.0.0.0 -Dpackaging=jar -DlocalRepositoryPath=$HOME/.m2/repository
mvn org.apache.maven.plugins:maven-install-plugin:3.1.1:install-file  -Dfile=libs/azure-core-http-okhttp-1.11.6.jar -DgroupId=com.azure.local -DartifactId=azure-core-http-okhttp -Dversion=1.11.6 -Dpackaging=jar -DlocalRepositoryPath=$HOME/.m2/repository


rm -rf "$HOME/.m2/repository/com/snc/commons-core-automation/19.0.0.0/_remote.repositories"
rm -rf "$HOME/.m2/repository/com/snc/snc-automation-api/19.0.0.0/_remote.repositories"
rm -rf "$HOME/.m2/repository/com/snc/commons-glide/19.0.0.0/_remote.repositories"
rm -rf "$HOME/.m2/repository/com/google/code/gson/gson/2.8.2/_remote.repositories"
rm -rf "$HOME/.m2/repository/com/google/guava/guava/2.8.2/_remote.repositories"
rm -rf "$HOME/.m2/repository/com/snc/mid/19.0.0.0/_remote.repositories"
rm -rf "$HOME/.m2/repository/com/azure/local/azure-core-http-okhttp/1.11.6/_remote.repositories"

rm -rf "$HOME/.m2/repository/com/snc/commons-core-automation/19.0.0.0/commons-core-automation-19.0.0.0.pom"
rm -rf "$HOME/.m2/repository/com/snc/snc-automation-api/19.0.0.0/snc-automation-api-19.0.0.0.pom"
rm -rf "$HOME/.m2/repository/com/snc/commons-glide/19.0.0.0/commons-glide-19.0.0.0.pom"
rm -rf "$HOME/.m2/repository/com/google/code/gson/gson/2.8.2/gson-2.8.2.pom"
rm -rf "$HOME/.m2/repository/com/google/guava/guava/2.8.2/guava-2.8.2.pom"
rm -rf "$HOME/.m2/repository/com/snc/mid/19.0.0.0/mid-19.0.0.0.pom"
rm -rf "$HOME/.m2/repository/com/azure/local/azure-core-http-okhttp/1.11.6/azure-core-http-okhttp-1.11.6.pom"