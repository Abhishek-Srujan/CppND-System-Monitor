# CppND-System-Monitor

In this System Monitor Project, a feature similar to that of htop is developed. 

## Implemented Changes
`ProcessParser` and `Process` classes

## To setup and compile in Ubuntu workspace:

1. Clone repository into `/home/workspace/

2. Install `ncurses` package
```
sudo apt-get install libncurses5-dev libncursesw5-dev
```
3. Compile and run
```
g++ -std="c++17" main.cpp -lncurses
./a.out
```
4. In case of error that looks like the following: 
```
root@77e30fca8a01:/home/workspace/CppND-Object-Oriented# ./a.out
*** %n in writable segment detected ***
                                      Aborted (core dumped)
```
just keep trying `./a.out` and it should work eventually!
