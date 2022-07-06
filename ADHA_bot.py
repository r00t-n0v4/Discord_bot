import asyncio
import ipinfo
import subprocess
import discord
import youtube_dl
import os
import socket
import random
import wolframalpha
import wikipedia
import time
import playsound
import datetime
import pickle
import shutil
import os.path
import requests
import json
import phonenumbers
import nmap
import whois
import string
import bluetooth
from shodan import Shodan
from Crypto.PublicKey import RSA 
from socket import *
from phonenumbers import geocoder, carrier, timezone
from bs4 import BeautifulSoup
from gtts import gTTS
import speech_recognition as sr
from discord.ext import commands
import scapy.all as scapy
import re
from re import sub
from exif import Image
from requests import get

#shodan api key
sho_key = Shodan("AweqFHRgO4faFkyMGH6nJMqYK015M6mF")
#security Trail API key
sec_key = "97xozZNdmzXNPMedpAd6TzykWR3jZDZ9"

#ipinfo API key
ipinfoapi_token = "c10f830e728ec5"

#crypto API key
crypt_key = "adb89034bdfeb53ac5327c0d82c17ac0c93ba958"

#wolframalpha key
wolf_client = wolframalpha.Client("PV8224-QKRUGU5QWT")

#abstact api key
abs_phone = "de6a239a4a814d118e4a9d291aa634cb"
abs_geo = "bdde82a979eb45edb036a1e96fb22d31"
abs_exchange = "44bbec28d92e4d14a0ff6bef864e7e6b"
abs_holiday = "aaa9ad785c0c4bd7ad49fcf35f0be17b"
abs_email = "24f14321ad354b68a0c4323ced94decf"

#discord key
Token = 'NjgwMDQzNTAzNzE5NDE1ODEw.Xk6J3Q.f71vdIvamjTrK_qtvuT_7EGK1Ns'
bot = commands.Bot(command_prefix=commands.when_mentioned_or("."),
                   description='ADHA AI assistant')
# Suppress noise about console usage from errors
youtube_dl.utils.bug_reports_message = lambda: ''


ytdl_format_options = {
    'format': 'bestaudio/best',
    'outtmpl': '%(extractor)s-%(id)s-%(title)s.%(ext)s',
    'restrictfilenames': True,
    'noplaylist': True,
    'nocheckcertificate': True,
    'ignoreerrors': False,
    'logtostderr': False,
    'quiet': True,
    'no_warnings': True,
    'default_search': 'auto',
    'source_address': '0.0.0.0' # bind to ipv4 since ipv6 addresses cause issues sometimes
}

ffmpeg_options = {
    'options': '-vn'
}

ytdl = youtube_dl.YoutubeDL(ytdl_format_options)

#only runs certain commands if its me
def is_it_me(ctx):
    return ctx.author.id == 296029433280856065, 149035802016481280


class YTDLSource(discord.PCMVolumeTransformer):
    def __init__(self, source, *, data, volume=0.5):
        super().__init__(source, volume)

        self.data = data

        self.title = data.get('title')
        self.url = data.get('url')

    @classmethod
    async def from_url(cls, url, *, loop=None, stream=False):
        loop = loop or asyncio.get_event_loop()
        data = await loop.run_in_executor(None, lambda: ytdl.extract_info(url, download=not stream))

        if 'entries' in data:
            # take first item from a playlist
            data = data['entries'][0]

        filename = data['url'] if stream else ytdl.prepare_filename(data)
        return cls(discord.FFmpegPCMAudio(filename, **ffmpeg_options), data=data)


class Music(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

#joins voice chat
    @commands.command()
    async def join(self, ctx, *, channel: discord.VoiceChannel):
        """Joins a voice channel"""

        if ctx.voice_client is not None:
            return await ctx.voice_client.move_to(channel)

        await channel.connect()


#Downloads then plays youtube video
    @commands.command()
    async def yt(self, ctx, *, url):
        """Plays from a url (almost anything youtube_dl supports)"""

        async with ctx.typing():
            player = await YTDLSource.from_url(url, loop=self.bot.loop)
            ctx.voice_client.play(player, after=lambda e: print('Player error: %s' % e) if e else None)

        await ctx.send('Now playing: {}'.format(player.title))

#Stops music & disconnects
    @commands.command()
    async def stop(self, ctx):
        """Stops and disconnects the bot from voice"""

        await ctx.voice_client.disconnect()

    async def ensure_voice(self, ctx):
        if ctx.voice_client is None:
            if ctx.author.voice:
                await ctx.author.voice.channel.connect()
            else:
                await ctx.send("You are not connected to a voice channel.")
                raise commands.CommandError("Author not connected to a voice channel.")
        elif ctx.voice_client.is_playing():
            ctx.voice_client.stop()


class Commands():
    #Events
    @bot.event
    async def on_ready():
        await bot.change_presence(status=discord.Status.idle, activity=discord.Game('in the mainframe ;)'))
        print('*'*60)
        print('   _____  ________    ___ ___    _____    ')
        print('  /  _  \ \______ \  /   |   \  /  _  \   ')
        print(' /  /_\  \ |    |  \/    ~    \/  /_\  \  ')
        print('/    |    \|    `   \    Y    /    |    \ ')
        print('\____|__  /_______  /\___|_  /\____|__  / ')
        print('        \/        \/       \/         \/  ')
        print('                                     Online!')
        print('*'*60)

    #When someone joins	
    @bot.event
    async def on_member_join(member):
        print(f'Welcome to Dedsec {member}! {member} has joined the server') 

    #when someone leaves
    @bot.event
    async def on_member_remove(member):
        print(f'{member} has left the server')
        

    #Error: event
    @bot.event
    async def on_command_error(ctx, error):
        if isinstance(error, commands.MissingRequiredArgument):
            await ctx.send('Error: Invalid command used!')

    #Gives commands
    @bot.command()
    async def bot_command(ctx):
        await ctx.send(f'''
        Here are all my commands: 
    Bot Commands:
            .bot_command (shows all commands)
            .password +lenght (random password sent to you)
            .wiki (wiki search API)
            .wolf (search via wolframe API)
            .searchuser (search user via username)
            .ports (finds open ports to website)(will send a shit ton of messages)
            .phoneinfo (+international code(number)will get you some info on the number and Using Abstract API)(etc. +18002655543)
            .hnews (latest hackernews)
            .ping (pings the mofo)
            .ipinfo (searches IP info using ipinfo.io API and Using Abstract API)
            .url2ip (change url to ip to then find more info using other commands)
            .subdom (find subdomains to url put in search)
            .emailcheck (check if an email can be sent to said person)
            .domaininfo (find info on domain name given)
            .weather (gives weather)
            .token (creates rsa token public and private keys)
            .crypto (send crypto rates based off of USD prices)
            .exchange (shows currency rates based off EURO)
            .flipcoin (flips coin)
            .diceroll (rolls dice)
            .urlshort (shortens url, made for sending malicious links)
            .urlcheck (checks if url in in the malicious database (internal))
            .imagedata takes metadata out of uploaded image and sends you the info
        ''')

    #secret Commands only certain people can use
    @bot.command()
    @commands.check(is_it_me)
    async def secret_command(ctx):
        await ctx.author.send(f'''
        Secret Commands:
        .shutdown (shuts down the server)
        .wipe (wipes server)
        .test (just does a test script)
        .ip (gives server IP)
        .wifinear (finds wifi near server)
        .blue (finds bluetooth around server)
        ''')    
        
    #bluetooth around me finds bluetooth devices
    @bot.command()
    @commands.check(is_it_me)
    async def blue(ctx):
        print("Scanning for bluetooth devices: ")
        await ctx.author.send("Scanning for bluetooth devices: ")
        devices = bluetooth.discover_devices(lookup_names = True)
        number_of_devices = len(devices)
        print(number_of_devices, "devices found")
        await ctx.author.send(number_of_devices, "devices found")
        for addr,name in devices:
            print("\n")
            print("Device Name: %s" % (name))
            await ctx.author.send("Device Name: {name}")
            print("Device MAC Address: %s" % (addr))
            await ctx.author.send("Device MAC Address: {addr}")
            print("Services Found:")
            await ctx.author.send("Services Found:")
            services = bluetooth.find_service(address=addr)

            if len(services) <=0:
                print("zero services found on", addr)
                await ctx.author.send("zero services found on {addr}")
            else:
                for serv in services:
                    print(serv['name'])
                    await ctx.author.send("{serv}['name']")
            print("\n")

    #ping to bot server 
    @bot.command()
    async def ping(ctx):
        await ctx.send(f'ping: {round(bot.latency * 1000)}ms')
        
        
    #Runs Shutdown script
    @bot.command()
    @commands.check(is_it_me)
    async def shutdown(ctx):
        await ctx.send(f'Shutting down ADHA bot server')
        os.system("shutdown /s /t 1");
        #subprocess.call([r'E:\DiscordBot\scripts\Shutdown_All.bat'])

    #Runs wipe script
    #DO NOT RUN UNLESS YOU HAVE TOO
    @bot.command()
    @commands.check(is_it_me)
    async def wipe(ctx):
        await ctx.send(f'Wipping server')
        subprocess.call([r'C:\Users\HuangNova\Documents\Discordbot\scripts\wipe.bat'])

        
    #Test script    
    @bot.command()
    @commands.check(is_it_me)
    async def test(ctx):
        await ctx.send('test script')
        subprocess.call([r'C:\Users\HuangNova\Documents\Discordbot\scripts\test.bat'])
        
    #IP scripts  
    @bot.command()
    @commands.check(is_it_me)
    async def ip(ctx):
        ip_address = get('https://api.ipify.org').text
        await ctx.author.send('Public IP: '+ip_address)
        #subprocess.call([r'E:\DiscordBot\scripts\ip.bat'])
    
    #IP Info
    @bot.command()
    async def ipinfo(ctx, ipadd):
        #send a link to the glasswire page for finding info on hosts
        await ctx.author.send("You might want to checkout this website:")
        await ctx.author.send(f"https://www.glasswire.com/host/{ipadd}")

        handler = ipinfo.getHandler(ipinfoapi_token)
        details = handler.getDetails(ipadd)
        await ctx.author.send("Searching info on: "+ipadd)
        await ctx.author.send("Here is what we found using IPinfo.io:")
        await ctx.author.send(details.all)
        #Abstract API 
        response = requests.get(f"https://ipgeolocation.abstractapi.com/v1/?api_key={abs_geo}&ip_address={ipadd}")
        await ctx.author.send("Searching info using AbstractAPI: "+ipadd)
        print(response.status_code)
        await ctx.author.send("Here is what we found using AbstractAPI:")
        info = response.content
        print(response.content)
        await ctx.author.send(info)

        #whois
        await ctx.author.send("Here is what we found using WhoIs: ")
        result = whois.whois(ipadd)
        with open("whois.txt", "w") as f:
                    print(result, file=f)
        await ctx.author.send(file = discord.File(r'C:\Users\r00t-n0v4\Documents\Scripts\Discordbot\whois.txt'))

        #lookup using sonar
        await ctx.author.send("Here is what we found using Sonar: ")
        resp = requests.get(f"https://sonar.omnisint.io/reverse/{ipadd}")
        sonar = resp.content
        with open("sonar_all.txt", "w") as f:
            print(sonar, file=f)
        with open("sonar_all.txt", "r") as infile, open ("sonar.txt", "w") as outfile:
             data = infile.read()
             data = data.replace(",", "\n")
             outfile.write(data)
        sonar_file = "C:\\Users\\r00t-n0v4\\Documents\\Scripts\\Discordbot\\sonar.txt"
        await ctx.author.send(file = discord.File(sonar_file))
        os.remove("whois.txt")
        os.remove("sonar.txt")
        os.remove("sonar_all.txt")

    #RSA Token Creator
    @bot.command()
    async def token(ctx):
        new_key = RSA.generate(2048, e=65537) 
        public_key = new_key.publickey().exportKey("PEM") 
        private_key = new_key.exportKey("PEM") 
        with open("rsa_public.txt", "w") as f:
            print(public_key, file=f)
        with open("rsa_private.txt", "w") as f:
            print(private_key, file=f)    
        await ctx.author.send("Here are your RSA keys")
        await ctx.author.send(file = discord.File(r'C:\Users\r00t-n0v4\Documents\Scripts\Discordbot\rsa_public.txt'))
        await ctx.author.send(file = discord.File(r'C:\Users\r00t-n0v4\Documents\Scripts\Discordbot\rsa_private.txt'))
        await ctx.author.send("These Files have now been earased forever")
        await ctx.author.send("Note: Do not lose that private key")
        os.remove('rsa_public.txt')
        os.remove('rsa_private.txt')
    
    #wifi networks near ADHA
    # using the check_output() for having the network term retrieval
    @bot.command()
    @commands.check(is_it_me)
    async def wifinear(ctx):
        devices = subprocess.check_output(['netsh','wlan','show','network'])
        
        # decode it to strings
        devices = devices.decode('ascii')
        devices = devices.replace("\r","")
        
        # displaying the information
        with open("wifinear.txt", "w") as f:
            print(devices, file=f)
        wifinear_path = "C:\\Users\\r00t-n0v4\\Documents\\Scripts\\Discordbot\\wifinear.txt"
        await ctx.author.send(file = discord.File(wifinear_path))
        os.remove(wifinear_path)
        
    #create a random password 
    @bot.command()
    async def password(ctx, amount=16):
        s = "abcdefghijklmnopqrstuvwxyz123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*(/)\{}"
        passwordlen = amount
        password = "".join(random.sample(s,passwordlen))
        await ctx.author.send(f'password: '+password)
        await ctx.channel.purge(limit=1)

    #searches wiki and gives answer based on peramiters 
    @bot.command()
    async def wiki(ctx, question): 
        wiki_res = wikipedia.summary(question, sentences=2)
        await ctx.send(f'wiki found: '+wiki_res)

    #searches using wolframalpha	
    @bot.command()
    async def wolf(ctx, question): 
        wolf_res = next(wolf_client.query(question).results).text
        await ctx.send(f'ADHA found: '+wolf_res)

    # port scanner	
    @bot.command()
    async def ports(ctx, ports):
        await ctx.author.send("Searching for open ports on: " +ports)
        print("starting search on: "+ports)
        targetIP = gethostbyname(ports)
        await ctx.author.send(f"{ports} : {targetIP}")
        print(targetIP)
        port_min = 20
        port_max = 65535
        open_ports = []
        nm = nmap.PortScanner()
        # We're looping over all of the ports in the specified range.
        for port in range(port_min, port_max + 1):
            try:
                # The result is quite interesting to look at. You may want to inspect the dictionary it returns. 
                # It contains what was sent to the command line in addition to the port status we're after. 
                # For in nmap for port 80 and ip 10.0.0.2 you'd run: nmap -oX - -p 89 -sV 10.0.0.2
                result = nm.scan(targetIP, str(port))
                # Uncomment following line and look at dictionary
                # print(result)
                # We extract the port status from the returned object
                port_status = (result['scan'][targetIP]['tcp'][port]['state'])
                print(f"Port {port} is {port_status}")
                await ctx.author.send(f"Port {port} is {port_status}")
            except:
                # We cannot scan some ports and this ensures the program doesn't crash when we try to scan them.
                print(f"Cannot scan port {port}.")
                await ctx.author.send(f"Cannot scan port {port}.")

    # phone number lookup	
    @bot.command()
    async def phoneinfo(ctx, number):
        await ctx.author.send("Searching info on: "+number)
        phone_number = phonenumbers.parse(number)
        geoz = (geocoder.description_for_number(phone_number, 'en'))
        carrierz = (carrier.name_for_number(phone_number, 'en'))
        timez = (timezone.time_zones_for_number(phone_number))
        await ctx.author.send(f"""Here is what we found: 
        Geolocation: {geoz}
        Carrier: {carrierz}
        Timezone: {timez}""")
        #Abstract API 
        await ctx.author.send("Searching info using AbstractAPI: "+number)
        response = requests.get(f"https://phonevalidation.abstractapi.com/v1/?api_key={abs_phone}&ip_address={number}")
        print(response.status_code)
        await ctx.author.send("Here is what we found: ")
        print(response.content)
        info = response.content
        await ctx.author.send(info)
        
    #Email verification
    @bot.command()
    async def emailcheck(ctx, emale):
        await ctx.author.send("Searching info using AbstractAPI: "+emale)
        response = requests.get(f"https://emailvalidation.abstractapi.com/v1/?api_key={abs_email}&email={emale}")
        info = response.content
        await ctx.author.send("Here is what we found:")
        await ctx.author.send(info)
        
    #Hackernews stories
    @bot.command()
    async def hnews(ctx):
        html_text = requests.get('https://thehackernews.com').text
        soup = BeautifulSoup(html_text, 'lxml')
        stories = soup.find_all('a', class_ = 'story-link')

        for story in stories:
            title = story.find('h2', class_ = 'home-title').text
            Author_date = story.find('div', class_ = 'item-label').text
            Short_des = story.find('div', class_ = 'home-desc').text

            await ctx.author.send(f"""
            Title: {title}
            -------------------------------------------
            Date / Author: {Author_date}
            -------------------------------------------
            Story: 
            {Short_des}
            -------------------------------------------
            """)    
        
    #Run Sherlock
    @bot.command()
    async def searchuser(ctx, user_name):
        await ctx.send(f'Searching user: '+user_name+ ' using sherlock')
        await ctx.author.send(f'Searching: '+user_name)
        path = 'C:\\Users\\r00t-n0v4\\sherlock\\sherlock'
        searching = 'python sherlock.py '+user_name
        file_name = ('\\'+user_name+'.txt')
        print (f'Searching for: '+user_name)
        os.chdir(path)
        os.system(searching)
        await ctx.author.send(f'Here is what we found on: '+user_name)
        file_path = path+file_name
        await ctx.author.send(file = discord.File(file_path))
        os.remove(file_path)

    #Grabify API Currently unavailable
    #@bot.command()
    #async def grab(ctx, web):
    #    url = "http://api.grabify.link/?key="

    #url shortener
    @bot.command()
    async def urlshort(ctx, web):
        url = "https://url-shortener-service.p.rapidapi.com/shorten"

        payload = (f"url=https%3A%2F%2F{web}")
        headers = {
            'content-type': "application/x-www-form-urlencoded",
            'x-rapidapi-host': "url-shortener-service.p.rapidapi.com",
            'x-rapidapi-key': "fc8e61d632mshbf92e24c2c569fdp150c08jsnfb8cf1a316c7"
            }

        response = requests.request("POST", url, data=payload, headers=headers)

        print(response.text) 
        url_short = response.text
        url_write = url_short.replace("\\", "")
        await ctx.author.send(url_short)
        with open("Bad_URL.txt", "a") as f:
            f.write(url_write)
            f.write("\n")

    #Check internal database if url is bad
    @bot.command()
    async def urlcheck(ctx, site):
        await ctx.author.send("Checking internal database if url is malicious: ")
        with open("Bad_URL.txt", "r") as f:
            if re.search(site, f.read()):
                await ctx.author.send("Do not click this has shown up in our malicious database!")
            else:
                await ctx.author.send("Clear to click")
            
    #turn url to ip
    @bot.command()
    async def url2ip(ctx, website):
        ip_add = gethostbyname(website)
        await ctx.author.send(f"""The IP for the {website} is: {ip_add}""")
    
    @bot.command()
    async def domaininfo(ctx, domname):
        #security Trails
        url = "https://api.securitytrails.com/v1/domain/"
        urldone = url+domname
        headers = {
            "Accept": "application/json",
            "APIKEY": "97xozZNdmzXNPMedpAd6TzykWR3jZDZ9"
        }

        response = requests.request("GET", urldone, headers=headers)

        await ctx.author.send("Here is what we found using Security Trails: ")
        print(response.text)
        trails_info = response.text
        with open("domaininfo.txt", "w") as f:
            print(trails_info, file=f)
        file_path = 'C:\\Users\\r00t-n0v4\\Documents\\Scripts\\Discordbot\\domaininfo.txt'
        await ctx.author.send(file = discord.File(file_path))

        #whois
        who_result = whois.whois(domname)
        with open("whois.txt", "w") as f:
                    print(who_result, file=f)
        file_whois = 'C:\\Users\\r00t-n0v4\\Documents\\Scripts\\Discordbot\\whois.txt'
        await ctx.author.send("Here is what we found using WhoIs: ")
        await ctx.author.send(file = discord.File(file_whois))
        os.remove(file_whois)
        os.remove(file_path)

    #find subdomains
    @bot.command()
    async def subdom(ctx, domain):
        await ctx.author.send("Finding subdomains for: "+domain)
        # read all subdomains
        file = open("subdomain_list.txt")
        # read all content
        content = file.read()
        # split by new lines
        subdomains = content.splitlines()
        # a list of discovered subdomains
        discovered_subdomains = []
        for subdomain in subdomains:
            # construct the url
            url = f"http://{subdomain}.{domain}"
            try:
                # if this raises an ERROR, that means the subdomain does not exist
                requests.get(url)
            except requests.ConnectionError:
                # if the subdomain does not exist, just pass, print nothing
                pass
            else:
                print("[+] Discovered subdomain:" +url)
                await ctx.author.send("[+] Discovered subdomain:" +url)
                # append the discovered subdomain to our list
                discovered_subdomains.append(url)

        #security Trails
        url1 = "https://api.securitytrails.com/v1/domain/"
        url2 = "/subdomains?children_only=false&include_inactive=true"
        url = url1+domain+url2

        headers = {
            "Accept": "application/json",
            "APIKEY": "97xozZNdmzXNPMedpAd6TzykWR3jZDZ9"
        }

        response = requests.request("GET", url, headers=headers)

        print(response.text)
        sec_sub = response.text
        with open("subdomain_find.txt", "w") as f:
            f.write(sec_sub)
        text = open("subdomain_find.txt")
        await ctx.author.send("Here is what we found using security trails: ")
        Sec_fileSubdom = 'C:\\Users\\r00t-n0v4\\Documents\\Scripts\\Discordbot\\subdomain_find.txt'
        await ctx.author.send(file = discord.File(Sec_fileSubdom))
        print("DONE!")

        #finding subdomains using sonar.omnisint.io
        await ctx.author.send("Here is what we found using Sonar: ")
        resp = requests.get(f"https://sonar.omnisint.io/subdomains/{domain}")
        sonar = resp.content
        with open("sonar_all.txt", "w") as f:
            print(sonar, file=f)
        with open("sonar_all.txt", "r") as infile, open ("sonar.txt", "w") as outfile:
             data = infile.read()
             data = data.replace(",", "\n")
             outfile.write(data)
        sonar_file = "C:\\Users\\r00t-n0v4\\Documents\\Scripts\\Discordbot\\sonar.txt"
        await ctx.author.send(file = discord.File(sonar_file))
        os.remove("sonar_all.txt")
        os.remove("sonar.txt")
        os.remove("subdomain_find.txt")
    
    #Weather
    @bot.command()
    async def weather(ctx, location):
        response = requests.get(f"http://api.weatherapi.com/v1/current.json?key=1ab57979cd40444a9de181750210511&q={location}&aqi=no")
        info = response.content
        with open("Weather_test.txt", "w") as x:
            print(info, file=x)
        with open("Weather_test.txt", "r") as infile, open ("Weather.txt", "w") as outfile:
             data = infile.read()
             data = data.replace(",", "\n")
             outfile.write(data)
        weather_file = 'C:\\Users\\r00t-n0v4\\Documents\\Scripts\\Discordbot\\Weather.txt'
        weather_test = 'C:\\Users\\r00t-n0v4\\Documents\\Scripts\\Discordbot\\Weather_test.txt'
        await ctx.author.send(file = discord.File(weather_file))
        os.remove(weather_file)
        os.remove(weather_test)

    #currency exchange
    @bot.command()
    async def exchange(ctx):
        url1 = "http://data.fixer.io/api/latest?access_key=5b126d77ad2add17e99f9c69be7c8b4f"
        response = requests.get(url1)
        exchange_rate = response.content
        with open("Exchange.txt", "w") as f:
            print(exchange_rate, file=f)
            f.close()
        with open("Exchange.txt", "r") as infile, open("Exchangerates.txt", "w") as outfile:
            data = infile.read()
            data = data.replace(",","\n")
            outfile.write(data)
        path = "C:\\Users\\r00t-n0v4\\Documents\\Scripts\\Discordbot\\Exchangerates.txt"  
        await ctx.author.send("Here are the exchange rates with the base of Euro: ")  
        await ctx.author.send(file = discord.File(path))
        os.remove("Exchange.txt")
        os.remove("Exchangerates.txt")

    #crypto currency exchange
    @bot.command()
    async def crypto(ctx):
        url = "https://api.coingecko.com/api/v3/global"
        response = requests.get(url)
        rates = response.content
        with open("crypto.txt", "w") as f:
            print(rates, file=f)
            f.close()
        with open("crypto.txt", "r") as infile, open("crypto_rate.txt", "w") as outfile:
            data = infile.read()
            data = data.replace(",","\n")
            outfile.write(data)
        path = "C:\\Users\\r00t-n0v4\\Documents\\Scripts\\Discordbot\\crypto_rate.txt"
        await ctx.author.send("Here are the crypto rates based on USD pricing: ")
        await ctx.author.send(file = discord.File(path))
        os.remove("crypto.txt")
        os.remove("crypto_rate.txt")

    #Get image / send metadata back
    @bot.command()
    async def imagedata(ctx):
        #Uploading photo portion 
        attachment = ctx.message.attachments[0]

        await ctx.author.send("Uploading file")
        await ctx.author.send(attachment.url)
        await attachment.save(attachment.filename)
        await ctx.author.send("File uploaded")

        #Reading metadata
        with open (attachment.filename, 'rb') as image_file:
            my_image = Image(image_file)

        with open("image_data.txt", "w") as f:
            print("Latitude data", file=f)
            print("-"*60, file=f)
            print(f"gps_latitude: {my_image.get('gps_latitude', 'Not found')}\n", file=f)
            print(f"gps_latitude_ref: {my_image.get('gps_latitude_ref', 'Not found')}\n", file=f)
            print(f"gps_longitude: {my_image.get('gps_longitude', 'Not found')}\n")
            print(f"gps_longitude_ref: {my_image.get('gps_longitude_ref', 'Not found')}\n", file=f)
            print("Other info\n", file=f)
            print("-"*60, file=f)
            print(f"Lens make: {my_image.get('lens_make', 'Unknown')}\n", file=f)
            print(f"Lens model: {my_image.get('lens_model', 'Unknown')}\n", file=f)
            print(f"Lens specification: {my_image.get('lens_specification', 'Unknown')}\n", file=f)
            print(f"OS version: {my_image.get('software', 'Unknown')}\n", file=f)
        path = "image_data.txt"
        await ctx.author.send(file = discord.File(path))
        #removing saved attachment
        os.remove(attachment.filename)
        os.remove(path)


    #flip a coin
    @bot.command()
    async def flipcoin(ctx):
            flip = random.randint(0, 1)
            if (flip == 0):
                await ctx.send("Heads")
            else:
                await ctx.send("Tails")

    #Dice Roll
    @bot.command()
    async def diceroll(ctx):
        await ctx.send(random.randint(1, 6))

    #purge messages	
    @bot.command()
    @commands.has_permissions(manage_messages=True)
    async def clear(ctx, amount=10):
        await ctx.channel.purge(limit=amount)
        
    #kick user
    @bot.command()
    async def kick(ctx, member : discord.Member, *, reason=None):
        await member.kick(reason=reason)
        await ctx.send(f'Kicked {member.mention}')
        
       
     #ban user
    @bot.command()
    async def ban(ctx, member : discord.Member, *, reason=None):
        await member.ban(reason=reason)
        await ctx.send(f'Banned {member.mention}')
        
        
    #unban user
    @bot.command()
    async def unban(ctx, *, member):
        banned_users = await ctx.guild.bans()
        member_name, member_discriminator = member.split('#')
        for ban_entry in banned_users:
            user = ban_entry.user
            
            if (user.name, user.discriminator) == (member_name, member_discriminator):
                await ctx.guild.unban(user)
                await ctx.send(f'Unbanned {user.mention}')
                return

bot.add_cog(Music(bot))
bot.run(Token)