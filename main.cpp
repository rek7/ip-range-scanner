#include <iostream>
#include <string>
#include <cstdlib>
#include <fstream>
#include <vector>
#include <sstream>
#include <ctime>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>

using namespace std;

#define INETADDR(a, b, c, d) (d + (c << 8) + (b << 16) + (a << 24)) //http://www.rohitab.com/discuss/topic/34061-cc-ip-address-algorithm/

class port_scan
{
  public:
    port_scan(string host, int port, int utime_out = 250000)  // .5 seconds aka 500 miliseconds 500000
    {
        scan_host = host;
        if((s0 = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            perror("error creating socket");
        }
        fcntl(s0, F_SETFL, O_NONBLOCK); // set to non-blocking
        scan_addr.sin_family = AF_INET; 
        scan_addr.sin_port = htons(port);
        if(inet_pton(AF_INET, (host).c_str(), &scan_addr.sin_addr)<=0)  
        { 
            perror("error creating socket");
        }
        timeout.tv_sec = 0;
        timeout.tv_usec = utime_out;
        setsockopt(s0, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
        setsockopt(s0, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
    }
    bool is_port_open(void)
    {
        fd_set s0_fd;
        connect(s0, (struct sockaddr *)&scan_addr, sizeof(scan_addr));
        FD_ZERO(&s0_fd);
        FD_SET(s0, &s0_fd);
        if (select(s0 + 1, 0, &s0_fd, 0, &timeout) == 1)
        {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(s0, SOL_SOCKET, SO_ERROR, &so_error, &len);
            if(so_error == 0)
            {
                return true;
            }
        }
        return false;
    }
    string send_http_request(void)
    {
        char buffer[1024] = {0};
        string request = "GET / HTTP/1.1\r\nHost: " + scan_host + "\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0\r\nConnection: close\r\n\r\n";
        fcntl(s0, F_SETFL, fcntl(s0, F_GETFL, 0) & ~O_NONBLOCK); // set socket back to blocking
        send(s0, request.c_str(), request.size(), 0);
        if(read(s0, buffer, sizeof(buffer)) > 0)
        {
            string buf = string(buffer);
            if(buf.find("HTTP/") != string::npos && buf.find("\r\n\r\n") != string::npos)
            {
                string header = buf.substr(0, buf.find("\r\n\r\n")),
                body = buf.substr(buf.find("\r\n\r\n"), buf.size()), ret_str;
                if(header.find("Server: ") != string::npos)
                {
                    int server_pos = header.find("Server: ")+8;
                    ret_str += "Webserver: '" + header.substr(server_pos, header.substr(server_pos).find("\r\n")) + "' ";
                }
                if(header.find("Location: ") != string::npos)
                {
                    int location_pos = header.find("Location: ")+10;
                    ret_str += "Redirect Location: '" + header.substr(location_pos, header.substr(location_pos).find("\r\n")) + "' ";
                }
                if(body.find("<title>") != string::npos && body.find("</title>") != string::npos)
                {
                    int title_pos = body.find("<title>")+7;
                    ret_str += "Title: '" + body.substr(title_pos, body.substr(title_pos).find("</title>")) + "'";
                }
                return ret_str;
            }
            else
            {
                return (buf.size() <= 50 ? buf : buf.substr(0, 50));
            }
        }
        return string();
    }
    ~port_scan(void)
    {
        close(s0);
    }

  private:
    struct timeval timeout = {0};
    struct sockaddr_in scan_addr = {0};
    int s0;
    string scan_host;
};

class misc
{
    public:
        vector<int> split_by_octet(string ip)
        {
            vector<int> octets;
            string octet;
            stringstream tmp_ss;
            tmp_ss << ip;
            while(getline(tmp_ss, octet, '.'))
            {
                octets.push_back(stoi(octet));
            }
            return octets;
        }
        vector<string> iter_ips(string from, string to)
        {
            vector<string> ips;
            //cout << "Iterating from: " << from << " To: " << to << endl;
            vector<int>from_octets = split_by_octet(from);
            vector<int>to_octets = split_by_octet(to);
            if(from_octets.size() == 4 && to_octets.size() == 4)
            {
                    unsigned char *ip;
                    unsigned long from = INETADDR(from_octets[0], from_octets[1], from_octets[2], from_octets[3]),
                    to = INETADDR(to_octets[0], to_octets[1], to_octets[2], to_octets[3]);
                    while(from <= to)
                    {
                        char ip_addr[16] = {0};
                        ip = (unsigned char *)&from;
                        sprintf(ip_addr, "%u.%u.%u.%u", ip[3], ip[2], ip[1], ip[0]);
                        ips.push_back(ip_addr);
                        ++from;
                    }
                    return ips;
            }
            else
            {
                cout << "[-] ERROR MALFORMED IP RANGES" << endl;
                exit(EXIT_FAILURE);
            }
        }
    
};

class start_scan
{
    public:
        void start(string ranges, string port, int thread_num = 10)
        {
            misc m;
            vector <int> ports;
            if(port.find(",") != string::npos)
            {
                stringstream tmp_ports;
                string buff;
                tmp_ports << port;
                while(getline(tmp_ports, buff, ','))
                {
                    ports.push_back(stoi(buff));
                }
            }
            else
            {
                ports.push_back(stoi(port));
            }
            int split_ranges_pos = ranges.find('-'), total_results = 0;
            vector<string> ips = m.iter_ips(ranges.substr(0, split_ranges_pos), ranges.substr(split_ranges_pos+1, ranges.size()));
            cout << "[+] Number of IPs to be scanned: " << ips.size() << endl;
            //cout << ips.size()/thread_num << endl;
            for(string &ip : ips)
            {
                int results_found = 0;
                for (int &check_port: ports)
                {
                    port_scan ps(ip, check_port); //209.85.200.100
                    if(ps.is_port_open())
                    {
                        string info = ps.send_http_request();
                        if(!info.empty())
                        {
                            cout << "\r[+] Found Results on host: " << ip << ":" << check_port << " " << info << endl;
                            ++results_found;
                            ++total_results;
                        }
                    }
                }
                cout << "\r[" << ((results_found >= 1) ? '+' : '-') << "] Finished Scanning: " << ip << ", " << results_found << " result(s) found.";
            }
            cout << endl << "[+] Done. Total Results found: " << total_results << endl;
        }
};

int main(int argc, char **argv) //80,443,8080,280,4443
{ 
    start_scan ss;
    if(argc == 3)
    {
        ss.start(argv[1], argv[2]);
        return EXIT_SUCCESS;
    }
    else
    {
        cout << "ERROR correct usage: " << argv[0] << " IPRange ListOfPorts" << endl
        << "Example: " << argv[0] << " \"127.0.0.0-127.0.0.255\" \"80,443,8080,280,4443\"" << endl;
        return EXIT_FAILURE;
    }
}
