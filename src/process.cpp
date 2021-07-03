#include <unistd.h>
#include <cctype>
#include <sstream>
#include <string>
#include <vector>

#include "process.h"
#include "linux_parser.h"

using std::string;
using std::to_string;
using std::vector;

Process::Process(int pid) {
  m_pid = pid;
  m_command = LinuxParser::Command(pid);
  std::string ram = LinuxParser::Ram(pid);
  m_ram = std::stol(ram);
  m_uptime = LinuxParser::UpTime(pid);
  m_user = LinuxParser::User(pid);

  long seconds = LinuxParser::UpTime() - m_uptime;
  long totaltime = LinuxParser::ActiveJiffies(pid);
  try {
    m_utilization = float(totaltime) / float(seconds);

  } catch (...) {
    m_utilization = 0;
  }
}
// TODO: Return this process's ID
int Process::Pid() const { return m_pid; }

// TODO: Return this process's CPU utilization
float Process::CpuUtilization() const { return m_utilization; }

// TODO: Return the command that generated this process
string Process::Command() const { return m_command; }

// TODO: Return this process's memory utilization
string Process::Ram() const { return std::to_string(m_ram); }

// TODO: Return the user (name) that generated this process
string Process::User() const { return m_user; }

int Process::getRam() const { return m_ram; }

// TODO: Return the age of this process (in seconds)
long int Process::UpTime() const { return m_uptime; }

// TODO: Overload the "less than" comparison operator for Process objects
// REMOVE: [[maybe_unused]] once you define the function
//bool Process::operator<(Process const& a) const { return CpuUtilization() < a.CpuUtilization();; }
bool Process::operator<(Process const& a) const {
    return CpuUtilization() < a.CpuUtilization();
}