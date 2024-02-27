from datetime import date,datetime
from socket import *
# import nmap
import os,sys

log_name = "./log_files/"

def main(ipaddress , port):
    print("[+] Honeypot Start ...... ")

    try:
        get_socket_con = socket(AF_INET,SOCK_STREAM)
        get_socket_con.bind((ipaddress,port))
        get_socket_con.listen(10)

        while 1:
            client_con,client_addr = get_socket_con.accept()
            print("Visiter found!  -  [{}]".format(client_addr[0]))

            # scan_visitor(client_addr[0])

            # Sending the response to the visitor
            # client_con.send(b"<h1> You Have Been Watching ! </h1>")
            data = client_con.recv(2048)

            print(data.decode('utf-8'))

    except error as identifier:
        print("[+] Unspecified error [{}]".format(identifier))

    except KeyboardInterrupt as key:
        print("[-] Process stopeed !")

    finally:
        get_socket_con.close()

    get_socket_con.close()

def scan_visitor(visiter_ip_address):

    today_date = date.today()
    datetime_now = datetime.now()
    dir_name = today_date.strftime("%d_%m_%Y")
    file_log_path = os.path.join(log_name,dir_name)

    isExist = os.path.exists(file_log_path)

    if(not isExist):
        os.mkdir(file_log_path)

    file_log_name = "/" + visiter_ip_address.replace(".","_") + " " + datetime.strftime(datetime_now,"%d_%m_%Y") + ".log"

    # print(file_log_name)
    print(file_log_path+file_log_name)

    isFile_Exist = os.path.isfile(file_log_path+file_log_name)

    if not isFile_Exist:
        is_write_or_append = "w"
    else:
        is_write_or_append = "a"
    
    with open(file_log_path+file_log_name , is_write_or_append) as fp:
        get_port_details = get_port_info(visiter_ip_address)
        # print(get_port_details)

        fp.write("\n")
        for disp in range(len(get_port_details) - 1):
            fp.write(str(get_port_details[disp]) + "\n")
        fp.write("\n")
        fp.close()

    print("[+] visiter scanning ! {} complete ".format(file_log_path+file_log_name))

def get_port_info(ip_address):
    scanner = nmap.PortScanner()
    scanner.scan(hosts=ip_address)
    ip_status = scanner[ip_address].state()
    print("[+] Scanning Visitor In Progress...")
    sc = {}
    for host in scanner.all_hosts():
        detail_info = []
        for proto in scanner[host].all_protocols():
            lport = scanner[host][proto].keys()
            sc = scanner[host][proto]
            for port in lport:
                a = "port : "+str(port) + " Service Name : " + sc[port]['name'] + "  Product Name : " + sc[port]['product']
                detail_info.append(a)

    return detail_info


if __name__ == "__main__":
    main("169.38.77.135",443)