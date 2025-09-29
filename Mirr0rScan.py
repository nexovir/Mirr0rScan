import colorama, time, subprocess, requests, argparse, os, pyfiglet, yaml, tempfile
from yaspin import yaspin  # type: ignore
from colorama import Fore, Style
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, parse_qs
from playwright.async_api import async_playwright
import asyncio
import json

colorama.init()

green = '\033[92m'
blue = '\033[94m'
cyan = '\033[34m'
yellow = '\033[33m'
red = '\033[91m'
reset = '\033[0m'


PROXIES = {
    "http": "socks5h://127.0.0.1:1080",
    "https": "socks5h://127.0.0.1:1080"
}


def discover_payloads (file : str, key) -> dict:
    with open(file, "r", encoding="utf-8") as f:
        data = json.load(f)

    return data[key]


parser = argparse.ArgumentParser(description='Mirr0rScan - A powerful scanner to discover Starting Points for vulnerabilities')

input_group = parser.add_argument_group('Input Options')

# --- Input Group ---
input_group = parser.add_argument_group('Input Options') 
input_group.add_argument('-l', '--urlspath', help='Path to file containing list of target URLs for discovery.', required=True) 
input_group.add_argument('-wl', '--wordlist', help='Path to a file containing parameters to FUZZ (By default, the program uses the parameters from the page itself for fuzzing. If you run it with the -he switch, it will re-fuzz all the parameters it has already discovered to find potential vulnerabilities. You can also provide additional parameters for fuzzing by using the -wl switch.) - (for example : wordlists/asset_note_wordlist.txt)',required=False)
input_group.add_argument('-hl', '--headerslist', help='Path to file containing list Headers - (for example : wordlists/headers-fuzz.txt)', required=False) 


# --- Configurations --- 
configue_group = parser.add_argument_group('Configurations')
configue_group.add_argument('-X', '--methods', help='HTTP methods to use for requests (default GET, POST, PUT, DELETE, PATCH)', type=str, default="GET,POST,PUT,DELETE,PATCH", required=False) 
configue_group.add_argument('-H', '--headers',help='Custom headers to include in requests (format: "Header: value" support multi -H)',action='append', required=False, default=[]) 
configue_group.add_argument('-x', '--proxy', help='HTTP proxy to use (e.g., http://127.0.0.1:8080)', type=str, default='', required=False) 
configue_group.add_argument('-he', '--heavy', help='If enabled, it re-fuzzes all discovered parameters after light completes (default: False)',action='store_true', default=False, required=False) 


# --- Vulnerabilities --- 
vulnerabilities_group = parser.add_argument_group('Vulnerabilities')
vulnerabilities_group.add_argument('-p', '--passive', help='Enable passive leak detection (emails, tokens, sensitive headers)', action='store_true', default=False)
vulnerabilities_group.add_argument('-sqli','--sqlinjection',help='Try to SQLinjection (\',",`) ', action='store_true', default=False)
vulnerabilities_group.add_argument('-bsqli','--blindsqlinjection',help='Try to Blind SQLinjection for Change Payloads Check \'blind_payloads.json\'', action='store_true' , required = False)



# --- Notification & Logging Group --- 
notif_group = parser.add_argument_group('Notification & Logging') 
notif_group.add_argument('-log', '--logger', help='Enable logger (default: logger.txt)', type=str, default='logger.txt', required=False) 
notif_group.add_argument('-s', '--silent', help='Disable prints output to the command line (default: False)', action='store_true', default=False, required=False) 
notif_group.add_argument('-d', '--debug', help='Enable Debug Mode (default: False)', action='store_true', default=False, required=False)
notif_group.add_argument('-n', '--notify', help='Enable notifications', action='store_true', default=False, required=False) 


# --- Rate Limit Options --- 
ratelimit_group = parser.add_argument_group('Rate Limit Options') 
ratelimit_group.add_argument('-t', '--thread',type=int,help='Number of concurrent threads to use (default: 1)',default=1, required=False) 
ratelimit_group.add_argument('-rd', '--delay',type=int,help='Delay (in seconds) between requests (default: 0)',default=0, required=False)


# --- Output --- 
output_group = parser.add_argument_group('Outputs') 
output_group.add_argument('-o', '--output',help='output file to write found issues/vulnerabilities ', type=str , default='reflix.output' , required=False) 
output_group.add_argument('-po', '--paramsoutput', help='Path to file where discovered parameters will be saved (default: all_params.txt)', required=False , default='all_params.txt') 
output_group.add_argument('-jo', '--jsonoutput',help='file to export results in JSON format',type=str ,required=False)

args = parser.parse_args()

# --- Input Group ---
urls_path = args.urlspath
wordlist_parameters = args.wordlist
wordlist_headers = args.headerslist


# --- Configurations --- 
methods = args.methods.split(',')
headers = {}
if args.headers:
    for header in args.headers:
        if ':' in header:
            key, value = header.split(':', 1)
            headers[key.strip()] = value.strip()
proxy = args.proxy
heavy = args.heavy


# --- Vulnerabilities --- 
passive = args.passive
sqli = args.sqlinjection
bsqli = args.blindsqlinjection
bsqlis = discover_payloads('blind_payloads.json', "Blind_SQLi") if bsqli else {}



# --- Notification & Logging Group --- 
logger = args.logger
silent = args.silent
debug = args.debug
notification = args.notify


# --- Rate Limit Options --- 
thread = args.thread
delay = args.delay


# --- Output --- 
output = args.output
params_output = args.paramsoutput
json_output = args.jsonoutput



def show_banner():
    banner = pyfiglet.figlet_format("Mirr0rScan")
    twitter = Style.BRIGHT + Fore.CYAN + "X.com: @nexovir" + Style.RESET_ALL
    version = Fore.LIGHTBLACK_EX + "v1.0.0" + Style.RESET_ALL
    total_width = 20
    twitter_centered = twitter.center(total_width)
    version_right = version.rjust(total_width)
    print(banner + twitter_centered + version_right + "\n")



def sendmessage(message: str, telegram: bool = False, colour: str = "YELLOW", logger: str = "logger.txt",
                silent: bool = False):
    color = getattr(colorama.Fore, colour, colorama.Fore.YELLOW)
    if not silent:
        if debug:
            print(color + message + colorama.Style.RESET_ALL)
    time_string = time.strftime("%d/%m/%Y, %H:%M:%S", time.localtime())
    if logger:
        try:
            with open(logger, 'a') as file:
                file.write(message + ' -> ' + time_string + '\n')
        except Exception:
            pass
    if telegram:
        bot_token = os.environ.get('BOT_TOKEN', '')
        if not bot_token:
            sendmessage("[WARN] BOT_TOKEN not set in environment", colour="YELLOW", logger=logger)
            return
        chat_id = os.environ.get('BOT_CHAT_ID', f"{BOT_CHAT_ID}")
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {'chat_id': chat_id, 'text': message}
        try:
            response = requests.post(url, data=payload, timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            try:
                with open(logger, 'a') as file:
                    file.write(f"[ERROR] Telegram message failed: {e}\n")
            except Exception:
                pass




async def read_write_list(list_data, file: str, type: str):
    def _read():
        if not os.path.exists(file):
            return []
        with open(file, 'r') as f:
            return list(set(line.strip() for line in f.read().splitlines() if line.strip()))
    def _write():
        with open(file, 'w') as f:
            for item in set(list_data):
                f.write(item.strip() + '\n')
    def _append():
        try:
            with open(file, 'r') as f:
                existing_items = set(f.read().splitlines())
        except FileNotFoundError:
            existing_items = set()
        with open(file, 'a') as f:
            for item in set(list_data):
                if item.strip() and item not in existing_items:
                    f.write(item.strip() + '\n')

    try:
        if type == "read" or type == 'r':
            return await asyncio.to_thread(_read)
        elif type == "write" or type == 'w':
            await asyncio.to_thread(_write)
            return
        elif type == "append" or type == 'a':
            await asyncio.to_thread(_append)
            return
    except Exception:
        return []




async def run_headless_scan(target_url, method="GET", search_word="nexovir", proxy="", headers=None):
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                ],
                proxy={"server": proxy} if proxy else None
            )
            context = await browser.new_context(
                user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
                extra_http_headers=headers or {},
                ignore_https_errors=True,
                viewport={"width": 1920, "height": 1080}
            )
            page = await context.new_page()
            await page.goto(target_url, wait_until="networkidle")
            html = await page.content()
            await browser.close()

            if search_word.lower() in html.lower():
                output_line = f"[{green}{method.upper()}{reset}] [{blue}http{reset}] [{cyan}info{reset}] [{yellow}DOM{reset}] {target_url}"
                print(output_line)
                await read_write_list([output_line], output, 'a')
                if xss:
                    await try_to_xss(target_url, method , 'DOM')
                return {"success": True, "url": target_url, "line": output_line}
            else:
                return {"success": False, "url": target_url}
    except Exception as e:
        sendmessage(f"[ERROR] Playwright scan failed: {str(e)}", colour="RED", logger=logger, silent=silent)
        return {"success": False, "url": target_url, "error": str(e)}



async def run_fallparams(url, proxy, thread, delay, method, headers):
    sendmessage(f"  [INFO] Starting parameter discovery and check reflection (method: {method}) {url}", colour="YELLOW", logger=logger, silent=silent)
    def _run():
        command = ["fallparams", "-u", url, "-x", proxy if proxy else '', "-X", 'GET POSt', '-silent', '-duc']
        for key, value in headers.items():
            command.extend(["-H", f"{key}: {value}"])
        result = subprocess.run(command, shell=False, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout.splitlines()
    try:
        parameters = await asyncio.to_thread(_run)
        sendmessage(f"      [INFO] {len(parameters)} parameters found ", logger=logger, silent=silent)
        return parameters
    except Exception as e:
        sendmessage(f"  [ERROR] Error fallparams URL {url}: {str(e)}", colour="RED", logger=logger, silent=silent)
        return []



async def discover_parameters(urls, proxy, thread, delay, methods):
    sendmessage(f"[INFO] Starting Discover Hidden Parameters (method : {methods}) ...", colour="YELLOW", logger=logger, silent=silent)
    await run_fallparams(url, proxy, thread, delay, method, headers)
    
    for url in urls:
        if passive:
            print('passive')

        for method in methods:
            parameters = await run_fallparams(url, proxy, thread, delay, method, headers)
            if not parameters:
                continue
            await read_write_list(parameters, params_output, 'a')
            await run_x8(url, parameters, proxy, thread, delay, method, headers, chunk, parameter)



async def main():
    try:
        show_banner() if not silent else None
        urls = await read_write_list("", urls_path, 'r')
        if not urls:
            sendmessage("[ERROR] No URLs loaded from urls_path", colour="RED", logger=logger)
            return
        
        await discover_parameters(urls , proxy , thread , delay , methods)
    
    except Exception as e:
        sendmessage(f"[ERROR] An error occurred: {str(e)}", telegram=notification, colour="RED", logger=logger, silent=silent)

if __name__ == "__main__":
    asyncio.run(main())
