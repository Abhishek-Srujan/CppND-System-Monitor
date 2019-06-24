#include <algorithm>
#include <iostream>
#include <math.h>
#include <thread>
#include <chrono>
#include <iterator>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include "constants.h"


using namespace std;

class ProcessParser{
private:
    std::ifstream stream;
    public:
    static string getCmd(string pid) ;
    static vector<string> getPidList() ;
    static std::string getVmSize(string pid) ;
    static std::string getCpuPercent(string pid) ;
    static long int getSysUpTime() ;
    static std::string getProcUpTime(string pid) ;
    static string getProcUser(string pid) ;
    static vector<string> getSysCpuPercent(string coreNumber = "") ;
    static float getSysRamPercent() ;
    static string getSysKernelVersion() ;
    static int getNumberOfCores(); 
    static int getTotalThreads(); 
    static int getTotalNumberOfProcesses() ;
    static int getNumberOfRunningProcesses(); 
    static string getOSName() ;
    static std::string PrintCpuStats(std::vector<std::string> values1, std::vector<std::string>values2) ;
    static bool isPidExisting(string pid);
	static float get_sys_active_cpu_time(vector<string> values) ;
	static float get_sys_idle_cpu_time(vector<string>values) ;
	
};

//Reading /proc/[PID]/cmdline to get command line information of any program 
string ProcessParser::getCmd(string pid)
{
	string line;
	// Opening stream for specific file
    ifstream stream;
    Util::getStream((Path::basePath() + pid + Path::cmdPath()), stream);
	//Get the cmdline and return that specific line
    std::getline(stream, line);
    return line;
}

// Get PID list from /proc/
vector<string> ProcessParser::getPidList()
{
    DIR* dir;
    // Basically, we  scan "/proc" dir for all directories with numbers as their names
    // If we get valid check we store dir names in vector as list of machine pids
    vector<string> container;
    if(!(dir = opendir("/proc")))
        throw std::runtime_error(std::strerror(errno));

    while (dirent* dirp = readdir(dir)) {
        // is this a directory?
        if(dirp->d_type != DT_DIR)
            continue;
        // Is every character of the name a digit?
        if (all_of(dirp->d_name, dirp->d_name + std::strlen(dirp->d_name), [](char c){ return std::isdigit(c); })) {
            container.push_back(dirp->d_name);
        }
    }
    
    if(closedir(dir))
        throw std::runtime_error(std::strerror(errno));
    return container;
}

//Reading /proc/[PID]/status for virtual memory status of specific process
string ProcessParser::getVmSize(string pid)
{
    string line;
    //Declaring search attribute for file
    string name = "VmData";
    string value;
    float result;
    // Opening stream for specific file
    ifstream stream;
    Util::getStream((Path::basePath() + pid + Path::statusPath()), stream);
    while(std::getline(stream, line)){
        // Searching line by line
        if (line.compare(0, name.size(),name) == 0) {
            // slicing string line on whitespace for values using sstream
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            //conversion kB -> GB
            result = (stof(values[1])/float(1024*1024));
            break;
        }
    }
    return to_string(result);
}

//Reading /proc/[PID]/stat for CPU percentage usage of specific process
std::string ProcessParser::getCpuPercent(string pid)
{
	string line;
	float result;
	// Opening stream for specific file
    ifstream stream;
    Util::getStream((Path::basePath() + pid + "/" + Path::statPath()), stream);
	std::getline(stream, line);
	//Slice the string line on whitespace for values using sstream
	istringstream buf(line);
	istream_iterator<string> beg(buf), end;
	vector<string> values(beg, end);
	
	float utime = stof (ProcessParser::getProcUpTime(pid));
	float stime = stof (values[14]);
	float cutime = stof (values[15]);
	float cstime = stof (values[16]);
	
	float starttime = stof (values[21]);
	float uptime = ProcessParser::getSysUpTime();
	float freq = sysconf(_SC_CLK_TCK); //Number of clock ticks per second, typically 100
	
	float total_time = utime + stime + cutime + cstime ;
	float seconds = uptime - (starttime/freq);
	result = 100.0 * ((total_time/freq)/seconds);
	
	return to_string(result);
	
}

//Reading /proc/uptime for determining the System uptime
long int ProcessParser::getSysUpTime()
{
	string line;
	// Opening stream for specific file
    ifstream stream;
    Util::getStream((Path::basePath() + Path::upTimePath()), stream);
	std::getline(stream, line);
	
	//Slice the string line on whitespace for values using sstream
	istringstream buf(line);
	istream_iterator<string> beg(buf), end;
	vector<string> values(beg, end);
	
	return stoi(values[0]);
}

//Reading /proc/[PID]/stat for determining the Process up time of a specific process
std::string ProcessParser::getProcUpTime(string pid)
{
	string line;
	// Opening stream for specific file
    ifstream stream;
	Util::getStream((Path::basePath() + pid + "/" + Path::statPath()), stream);
	std::getline(stream, line);
	
	//Slice the string line on whitespace for values using sstream
	istringstream buf(line);
	istream_iterator<string> beg(buf), end;
	vector<string> values(beg, end);
	
	return to_string(float(stof(values[13])/sysconf(_SC_CLK_TCK)));
}

//Reading /proc/[PID]/stat and /etc/passwd to obtain the process username
string ProcessParser::getProcUser(string pid)
{
	string line = "";
	string name = "Uid:";
	string result = "";
	// Opening stream for specific file
    ifstream stream;
	Util::getStream((Path::basePath() + pid + Path::statusPath()), stream);
	
	//Get UID
	while(std::getline(stream,line))
	{
		if (line.compare(0, name.size(),name) == 0) {
            // slicing string line on whitespace for values using sstream
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            result = values[1];
            break;
        }
	}
	
	//Get Proc User name corresponding to UID
	// Opening stream for specific file
    stream.close();
	Util::getStream("/etc/passwd", stream);
	name = "x:" + result;
	while(std::getline(stream,line))
	{
		// Only if found, select the substring from 0 to the first index of :
		if (line.find(name) != string::npos) {
            result = line.substr(0, line.find(":"));
            return result;
        }
	}
	return ""; // If not found return empty string	
}

//Reading /proc/cpuinfo to determine the number of cores
int ProcessParser::getNumberOfCores()
{
	ifstream stream;
	string line = "";
	string name = "cpu cores";
	Util::getStream (Path:: basePath() + "cpuinfo", stream);
	while(std::getline(stream, line))
	{
		if(line.compare(0, name.size(), name) == 0)
		{
			istringstream buf(line);
			istream_iterator<string> beg(buf), end;
			vector<string> values (beg, end);
			return stoi(values[3]);
		}
	}
	return 0;
}


//Read /proc/stat and get system cpu percentage for the specific core
vector<string> ProcessParser::getSysCpuPercent(string coreNumber)
{
	ifstream stream;
	string line = "";
	string name = "cpu" + coreNumber; 
	Util::getStream (Path:: basePath() + Path::statPath(), stream);
	while(std::getline(stream, line))
	{
		if(line.compare(0, name.size(), name) == 0)
		{
			istringstream buf(line);
			istream_iterator<string> beg(buf), end;
			vector<string> values (beg, end);
			return values;
		}
	}
	return (vector<string>());
}

float ProcessParser::get_sys_active_cpu_time(vector<string> values)
{
    return (stof(values[S_USER]) +
            stof(values[S_NICE]) +
            stof(values[S_SYSTEM]) +
            stof(values[S_IRQ]) +
            stof(values[S_SOFTIRQ]) +
            stof(values[S_STEAL]) +
            stof(values[S_GUEST]) +
            stof(values[S_GUEST_NICE]));
}

float ProcessParser::get_sys_idle_cpu_time(vector<string>values)
{
    return (stof(values[S_IDLE]) + stof(values[S_IOWAIT]));
}

//Prints CPU stats by taking two different times
string ProcessParser::PrintCpuStats(vector<string> values1, vector<string> values2)
{
/*
Because CPU stats can be calculated only if you take measures in two different time,
this function has two parameters: two vectors of relevant values.
We use a formula to calculate overall activity of processor.
*/
    float activeTime = ProcessParser::get_sys_active_cpu_time(values2) - ProcessParser::get_sys_active_cpu_time(values1);
    float idleTime = ProcessParser::get_sys_idle_cpu_time(values2) - ProcessParser::get_sys_idle_cpu_time(values1);
    float totalTime = activeTime + idleTime;
    float result = 100.0*(activeTime / totalTime);
    return to_string(result);
}

//Reads /proc/meminfo and determines system RAM percentage
float ProcessParser::getSysRamPercent()
{
	ifstream stream;
	string line = "";
	string name1 = "MemAvailable:";
	string name2 = "Memfree:";
	string name3 = "Buffers:";
	
	float totalMem = 0;
	float freemem = 0;
	float buffers = 0;
	Util::getStream (Path::basePath() + Path::memInfoPath(), stream);
	
	while(std::getline(stream, line))
	{
		 if (totalMem != 0 && freemem != 0)
            break;
		
		if(line.compare(0, name1.size(), name1) == 0)
		{
			istringstream buf(line);
			istream_iterator<string> beg(buf), end;
			vector<string> values (beg, end);
			totalMem = stof(values[1]);
		}
		
		if(line.compare(0, name2.size(), name2) == 0)
		{
			istringstream buf(line);
			istream_iterator<string> beg(buf), end;
			vector<string> values (beg, end);
			freemem = stof(values[1]);
		}
		
		if(line.compare(0, name3.size(), name3) == 0)
		{
			istringstream buf(line);
			istream_iterator<string> beg(buf), end;
			vector<string> values (beg, end);
			buffers = stof(values[1]);
		}
	}
	
    return float(100.0*(1-(freemem/(totalMem-buffers))));
}

//Read /proc/version/ and Get system kernel version
string ProcessParser::getSysKernelVersion()
{
	ifstream stream;
	string line = "";
	string name = "Linux version ";
	
	Util::getStream (Path::basePath() + Path::versionPath(), stream);
	
	while(std::getline(stream, line))
	{
		if(line.compare(0, name.size(), name) == 0)
		{
			istringstream buf(line);
			istream_iterator<string> beg(buf), end;
			vector<string> values (beg, end);
			return values[2];
		}
	}
	return "";
}

//Read /etc/os-release and determine OS Name
string ProcessParser::getOSName()
{
	ifstream stream;
	string line = "";
	string name = "PRETTY_NAME=";
	Util::getStream ("/etc/os-release", stream);
	
	while(std::getline(stream, line))
	{
		if(line.compare(0, name.size(), name) == 0)
		{
			std::size_t found = line.find("=");
		    found++;
		    string result = line.substr(found);
		    result.erase(std::remove(result.begin(), result.end(), '"'), result.end());
		    return result;
		}
	}
	return "";
}

//Get every process and read their number of threads
int ProcessParser::getTotalThreads()
{
	vector<string> pids = ProcessParser::getPidList();
	ifstream stream;
	string line = "";
	int number_of_threads = 0;
	for (auto i : pids)
	{
		Util::getStream (Path::basePath() + i + Path::statusPath(), stream);
		string name = "Threads=";
		while(std::getline(stream, line))
		{
			if(line.compare(0, name.size(), name) == 0)
			{
				istringstream buf(line);
				istream_iterator<string> beg(buf), end;
				vector<string> values (beg, end);
				number_of_threads += stoi(values[1]);
				break;
			}
		}
	}
	
	return number_of_threads;
}

// Read /proc/stat and get total number of processes
int ProcessParser::getTotalNumberOfProcesses()
{
	ifstream stream;
	string line = "";
	string name = "processes";
	Util::getStream (Path::basePath() + Path::statPath(), stream);
	while(std::getline(stream, line))
	{
		if(line.compare(0, name.size(), name) == 0)
		{
			istringstream buf(line);
			istream_iterator<string> beg(buf), end;
			vector<string> values (beg, end);
			return (stoi(values[1]));
		}
	}
	return 0;
}

// Read /proc/stat and get total number of running processes
int ProcessParser::getNumberOfRunningProcesses()
{
	ifstream stream;
	string line = "";
	string name = "procs_running";
	Util::getStream (Path::basePath() + Path::statPath(), stream);
	while(std::getline(stream, line))
	{
		if(line.compare(0, name.size(), name) == 0)
		{
			istringstream buf(line);
			istream_iterator<string> beg(buf), end;
			vector<string> values (beg, end);
			return (stoi(values[1]));
		}
	}
	return 0;
}

// Check if PID is existing
bool ProcessParser::isPidExisting(string pid)
{
	vector<string> pids = ProcessParser::getPidList();
	for(auto i : pids)
	{
		if (i == pid)
				return true;
	}
	return false;
}
