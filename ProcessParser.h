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
    static string getCmd(string pid) //D;
    static vector<string> getPidList() //D;
    static std::string getVmSize(string pid) //D;
    static std::string getCpuPercent(string pid) //D;
    static long int getSysUpTime() //D;
    static std::string getProcUpTime(string pid) //D;
    static string getProcUser(string pid) //D;
    static vector<string> getSysCpuPercent(string coreNumber = "") //D;
    static float getSysRamPercent() //D;
    static string getSysKernelVersion() //D;
    static int getNumberOfCores(); //D
    static int getTotalThreads(); //D
    static int getTotalNumberOfProcesses() //D;
    static int getNumberOfRunningProcesses(); //D
    static string getOSName() //D;
    static std::string PrintCpuStats(std::vector<std::string> values1, std::vector<std::string>values2) //D;
    static bool isPidExisting(string pid);
	static float get_sys_active_cpu_time(vector<string> values) //D;
	static float get_sys_idle_cpu_time(vector<string>values) //D;
	
};

//Reading /proc/[PID]/cmdline to get command line information of any program 
static string ProcessParser::getCmd(string pid)
{
	string line;
	// Opening stream for specific file
    ifstream stream = Util::getStream((Path::basePath() + pid + Path::cmdPath()));
	//Get the cmdline and return that specific line
    std::getline(stream, line);
    return line;
}

// Get PID list from /proc/
static vector<string> ProcessParser::getPidList()
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
static string ProcessParser::getVmSize(string pid)
{
    string line;
    //Declaring search attribute for file
    string name = "VmData";
    string value;
    float result;
    // Opening stream for specific file
    ifstream stream = Util::getStream((Path::basePath() + pid + Path::statusPath()));
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
static std::string ProcessParser::getCpuPercent(string pid)
{
	string line;
	float result;
	// Opening stream for specific file
    ifstream stream = Util::getStream((Path::basePath() + pid + "/" + Path::statPath()));
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
static long int ProcessParser::getSysUpTime()
{
	string line;
	// Opening stream for specific file
    ifstream stream;
    Util::getStream((Path::basePath() + "/" + Path::uptimePath()), stream);
	std::getline(stream, line);
	
	//Slice the string line on whitespace for values using sstream
	istringstream buf(line);
	istream_iterator<string> beg(buf), end;
	vector<string> values(beg, end);
	
	return stoi(values[0]);
}

//Reading /proc/[PID]/stat for determining the Process up time of a specific process
static std::string ProcessParser::getProcUpTime(string pid)
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
static string ProcessParser::getProcUser(string pid)
{
	string line;
	string name = "Uid:";
	string result = "";
	// Opening stream for specific file
    ifstream stream;
	Util::getStream((Path::basePath() + pid + "/" + Path::statPath()), stream);
	
	//Get UID
	while(getline(stream,line))
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
    ifstream stream;
	Util::getStream("/etc/passwd", stream);
	name = "x:" + result;
	while(getline(stream,line))
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
static int ProcessParser::getNumberOfCores()
{
	ifstream stream;
	string line = "";
	string name = "cpu cores";
	Util::getStream (Path:: basePath() + "cpuinfo", stream);
	while(getline(stream, line))
	{
		if(line.compare(0, name.size(), name) == 0)
		{
			istringstream buf(line);
			istream_iterator beg(buf), end;
			vector<string> values (beg, end);
			return stoi(values[3]);
		}
	}
	return 0;
}

//Read /proc/stat and get system cpu percentage for the specific core
static vector<string> ProcessParser::getSysCpuPercent(string coreNumber = "")
{
	ifstream stream;
	string line = "";
	string name = "cpu" + coreNumber; 
	Util::getStream (Path:: basePath() + Path:: statPath, stream);
	while(getline(stream, line))
	{
		if(line.compare(0, name.size(), name) == 0)
		{
			istringstream buf(line);
			istream_iterator beg(buf), end;
			vector<string> values (beg, end);
			return values;
		}
	}
	return (vector<string>());
}

static float ProcessParser::get_sys_active_cpu_time(vector<string> values)
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

static float ProcessParser::get_sys_idle_cpu_time(vector<string>values)
{
    return (stof(values[S_IDLE]) + stof(values[S_IOWAIT]));
}

//Prints CPU stats by taking two different times
string ProcessParser::printCpuStats(vector<string> values1, vector<string> values2)
{
/*
Because CPU stats can be calculated only if you take measures in two different time,
this function has two parameters: two vectors of relevant values.
We use a formula to calculate overall activity of processor.
*/
    float activeTime = getSysActiveCpuTime(values2) - getSysActiveCpuTime(values1);
    float idleTime = getSysIdleCpuTime(values2) - getSysIdleCpuTime(values1);
    float totalTime = activeTime + idleTime;
    float result = 100.0*(activeTime / totalTime);
    return to_string(result);
}

//Reads /proc/meminfo and determines system RAM percentage
static float ProcessParser::getSysRamPercent()
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
	
	while(getline(stream, line))
	{
		 if (totalMem != 0 && freemem != 0)
            break;
		
		if((line.compare(0), name1.size(), name1) == 0)
		{
			istringstream buf(line);
			istream_iterator beg(buf), end;
			vector<string> values (beg, end);
			totalMem = stof(values[1]);
		}
		
		if((line.compare(0), name2.size(), name2) == 0)
		{
			istringstream buf(line);
			istream_iterator beg(buf), end;
			vector<string> values (beg, end);
			freemem = stof(values[1]);
		}
		
		if((line.compare(0), name3.size(), name3) == 0)
		{
			istringstream buf(line);
			istream_iterator beg(buf), end;
			vector<string> values (beg, end);
			buffers = stof(values[1]);
		}
	}
	
    return float(100.0*(1-(freemem/(totalMem-buffers))));
}

//Read /proc/version/ and Get system kernel version
static string ProcessParser::getSysKernelVersion()
{
	ifstream stream;
	string line = "";
	string name = "Linux Version ";
	
	Util::getStream (Path::basePath() + versionPath(), stream);
	
	while(getline(stream, line))
	{
		if((line.compare(0), name.size(), name) == 0)
		{
			istringstream buf(line);
			istream_iterator beg(buf), end;
			vector<string> values (beg, end);
			return values[2];
		}
	}
	return "";
}

//Read /etc/os-release and determine OS Name
static string ProcessParser::getOSName()
{
	ifstream stream;
	string line = "";
	string name = "PRETTY_NAME=";
	Util::getStream ("/etc/os-release", stream);
	
	while(getline(stream, line))
	{
		if((line.compare(0), name.size(), name) == 0)
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
static int ProcessParser::getTotalThreads()
{
	vector<string> pids = ProcessParser::getPidList();
	ifstream stream;
	string line = "";
	int number_of_threads = 0;
	for (auto i in pids)
	{
		Util::getStream (Path::basePath() + i + Path::statusPath(), stream);
		string name = "Threads=";
		while(getline(stream, line))
		{
			if((line.compare(0), name.size(), name) == 0)
			{
				istringstream buf(line);
				istream_iterator beg(buf), end;
				vector<string> values (beg, end);
				number_of_threads += stoi(values[1]));
				break;
			}
		}
	}
	
	return number_of_threads;
}

// Read /proc/stat and get total number of processes
static int ProcessParser::getTotalNumberOfProcesses()
{
	ifstream stream;
	string line = "";
	string name = "processes"
	Util::getStream (Path::basePath() + statPath(), stream);
	while(getline(stream, line))
	{
		if((line.compare(0), name.size(), name) == 0)
		{
			istringstream buf(line);
			istream_iterator beg(buf), end;
			vector<string> values (beg, end);
			return (stoi(values[1]));
		}
	}
	return 0;
}

// Read /proc/stat and get total number of running processes
static int ProcessParser::getNumberOfRunningProcesses()
{
	ifstream stream;
	string line = "";
	string name = "procs_running"
	Util::getStream (Path::basePath() + statPath(), stream);
	while(getline(stream, line))
	{
		if((line.compare(0), name.size(), name) == 0)
		{
			istringstream buf(line);
			istream_iterator beg(buf), end;
			vector<string> values (beg, end);
			return (stoi(values[1]));
		}
	}
	return 0;
}

// Check if PID is existing
static bool ProcessParser::isPidExisting(string pid)
{
	vector<string> pids = ProcessParser::getPidList();
	for(auto i in pids)
	{
		if (i == pid)
				return True;
	}
	return False;
}
