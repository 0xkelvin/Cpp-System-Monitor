#include <dirent.h>
#include <unistd.h>
#include <sstream>
#include <string>
#include <vector>

#include "linux_parser.h"

using std::stol;
using std::stof;
using std::string;
using std::to_string;
using std::vector;

// DONE: An example of how to read data from the filesystem
string LinuxParser::OperatingSystem() {
  string line;
  string key;
  string value;
  std::ifstream filestream(kOSPath);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::replace(line.begin(), line.end(), ' ', '_');
      std::replace(line.begin(), line.end(), '=', ' ');
      std::replace(line.begin(), line.end(), '"', ' ');
      std::istringstream linestream(line);
      while (linestream >> key >> value) {
        if (key == "PRETTY_NAME") {
          std::replace(value.begin(), value.end(), '_', ' ');
          return value;
        }
      }
    }
  }
  return value;
}

// DONE: An example of how to read data from the filesystem
string LinuxParser::Kernel() {
  string os, kernel, version;
  string line;
  std::ifstream stream(kProcDirectory + kVersionFilename);
  if (stream.is_open()) {
    std::getline(stream, line);
    std::istringstream linestream(line);
    linestream >> os >> version >> kernel;
  }
  return kernel;
}

// BONUS: Update this to use std::filesystem
vector<int> LinuxParser::Pids() {
  vector<int> pids;
  DIR* directory = opendir(kProcDirectory.c_str());
  struct dirent* file;
  while ((file = readdir(directory)) != nullptr) {
    // Is this a directory?
    if (file->d_type == DT_DIR) {
      // Is every character of the name a digit?
      string filename(file->d_name);
      if (std::all_of(filename.begin(), filename.end(), isdigit)) {
        int pid = stoi(filename);
        pids.push_back(pid);
      }
    }
  }
  closedir(directory);
  return pids;
}

// TODO: Read and return the system memory utilization
float LinuxParser::MemoryUtilization() 
{ 
  string line, key;
  float TotalMemory, FreeMemory;
  std::ifstream filestream(kProcDirectory + kMeminfoFilename);
  if(filestream.is_open())
  {
    while (std::getline(filestream,line))
    {
      std::istringstream linestream(line);
      linestream >> key;
      if(key == "MemTotal:")
      {
        linestream >> TotalMemory;
      }
      else if (key == "MemFree:")
      {
        linestream >> FreeMemory;
        break;
      }
    }
  }
  return (TotalMemory - FreeMemory)/TotalMemory; 
}

// TODO: Read and return the system uptime
long LinuxParser::UpTime() { 
  // Read and return the system uptime
  long uptime;
  string line, uptimeStr;
  std::ifstream stream(kProcDirectory + kUptimeFilename);
  if (stream.is_open()) {
    std::getline(stream, line);
    std::istringstream uptimeStream(line);
    uptimeStream >> uptimeStr;
  }
  uptime = std::stol(uptimeStr);
  return uptime;
}

// TODO: Read and return the number of jiffies for the system
long LinuxParser::Jiffies() { 

  return LinuxParser::ActiveJiffies() + LinuxParser::IdleJiffies(); 
}

// TODO: Read and return the number of active jiffies for a PID
// REMOVE: [[maybe_unused]] once you define the function
long LinuxParser::ActiveJiffies(int pid) { 
  long total;
  string line, value;
  vector<string> values;
  
  std::ifstream filestream(kProcDirectory + std::to_string(pid) + kStatFilename);
  if(filestream.is_open()){
    std::getline(filestream, line);
    std::istringstream stringline(line);

    while(stringline >> value){
      values.push_back(value);
    } 
  }
    // make sure parsing was correct and values was read
  long utime = 0, stime = 0 , cutime = 0, cstime = 0;
  if (std::all_of(values[13].begin(), values[13].end(), isdigit)) 
    utime = stol(values[13]);
  if(std::all_of(values[14].begin(), values[14].end(), isdigit))
    stime = stol(values[14]);
  if(std::all_of(values[15].begin(), values[15].end(), isdigit))
    cutime = stol(values[15]);
  if(std::all_of(values[16].begin(), values[16].end(), isdigit))
    cstime = stol(values[16]);

 total = utime + stime + cutime + cstime;
return total/sysconf(_SC_CLK_TCK); 
}

// TODO: Read and return the number of active jiffies for the system
long LinuxParser::ActiveJiffies() {
  
  auto jiffies = LinuxParser::CpuUtilization();
  
  return stol(jiffies[CPUStates::kUser_]) + stol(jiffies[CPUStates::kNice_]) +
         stol(jiffies[CPUStates::kSystem_]) + stol(jiffies[CPUStates::kIRQ_]) +
         stol(jiffies[CPUStates::kSoftIRQ_]) +
         stol(jiffies[CPUStates::kSteal_]);
}

// TODO: Read and return the number of idle jiffies for the system
long LinuxParser::IdleJiffies() {
  
  auto jiffies = LinuxParser::CpuUtilization();
  
  return stol(jiffies[CPUStates::kIdle_]) + stol(jiffies[CPUStates::kIOwait_]); 
}

// TODO: Read and return CPU utilization
vector<string> LinuxParser::CpuUtilization() { 

  string line, cpu, value;  
  vector<string> jiffies;
  std::ifstream filestream(kProcDirectory + kStatFilename);


  if(filestream.is_open())
  {
    std::getline(filestream,line);
    std::istringstream linestream(line);

    linestream >> cpu;
    while (linestream >> value)
    {
      jiffies.push_back(value);
      /* code */
    }
  }
  return jiffies; 
}

// TODO: Read and return the total number of processes
int LinuxParser::TotalProcesses() {
  // Read and return the total number of processes
  int processes;
  string key, line;
  std::ifstream stream(kProcDirectory + kStatFilename);
  if (stream.is_open()) {
    while (std::getline(stream, line)) {
      std::istringstream linestream(line);
      linestream >> key;
      if (key == "processes") {
        linestream >> processes;
        break;
      }
    }
  }
  return processes;
}

// TODO: Read and return the number of running processes
int LinuxParser::RunningProcesses() {
  int processes;
  string key, line;
  std::ifstream stream(kProcDirectory + kStatFilename);
  if (stream.is_open()) {
    while (std::getline(stream, line)) {
      std::istringstream linestream(line);
      linestream >> key;
      if (key == "procs_running") {
        linestream >> processes;
        break;
      }
    }
  }
  return processes;
}

// TODO: Read and return the command associated with a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::Command(int pid) 
{
    string command;
  std::ifstream stream(kProcDirectory + std::to_string(pid) + kCmdlineFilename);
  if (stream.is_open()) {
    std::getline(stream, command);
  }
  return command;
}
// TODO: Read and return the memory used by a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::Ram(int pid) {
  string line, temp, VmSize;
  long mem;
  std::ifstream filestream(kProcDirectory + std::to_string(pid) +
                           kStatusFilename);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::istringstream streamline(line);
      streamline >> temp;
      if (temp == "VmSize:") {
        streamline >> mem;
        mem /= 1000;
        VmSize = std::to_string(mem);
      }
    }
  }

  return VmSize;
}

// TODO: Read and return the user ID associated with a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::Uid(int pid) {
  string line, key, uid;
  std::ifstream streamfile(kProcDirectory + std::to_string(pid) +
                           kStatusFilename);
  if (streamfile.is_open()) {
    while (std::getline(streamfile, line)) {
      std::istringstream streamline(line);

      streamline >> key;
      if (key == "Uid:") {
        streamline >> uid;
        break;
      }
    }
  }
  return uid;
}

// TODO: Read and return the user associated with a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::User(int pid) {
  string name, temp, x, id, line;
  string uid = LinuxParser::Uid(pid);
  std::ifstream filestream(kPasswordPath);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::replace(line.begin(), line.end(), ':', ' ');
      std::istringstream streamline(line);

      streamline >> temp >> x >> id;
      if (id == uid) {
        name = temp;
        break;
      }
    }
  }

  return name;
}

// TODO: Read and return the uptime of a process
// REMOVE: [[maybe_unused]] once you define the function
long LinuxParser::UpTime(int pid) {
long starttime;
vector<string> values;
string line, value;

std::ifstream filestream(kProcDirectory + std::to_string(pid) + kStatFilename);
if(filestream.is_open())
{
  std::getline(filestream, line);
  std::istringstream streamline(line);

  while(streamline >> value)
  {
    values.push_back(value);
  }
}
try {
  starttime = stol(values[21]) / sysconf(_SC_CLK_TCK);
} catch (...) {
  starttime = 0;
}
  return starttime;
}
