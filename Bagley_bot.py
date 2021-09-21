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
import os.path
import requests
import json
import phonenumbers
import nmap
from socket import *
from phonenumbers import geocoder, carrier, timezone
from bs4 import BeautifulSoup
from gtts import gTTS
import speech_recognition as sr
from discord.ext import commands
import scapy.all as scapy
import re


#ipinfo API key
ipinfoapi_token = "API KEY"

#wolframalpha key
wolf_client = wolframalpha.Client("API KEY")

#abstact api key
abs_phone = "API KEY"
abs_geo = "API KEY"
abs_exchange = "API KEY"
abs_holiday = "API KEY"
abs_email = "API KEY"

#discord key
Token = 'API KEY'
bot = commands.Bot(command_prefix=commands.when_mentioned_or("."),
                   description='Bagley AI assistant')
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
    return ctx.author.id == "Discord ID"


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

#plays music
    @commands.command()
    async def play(self, ctx, *, query):
        """Plays a file from the local filesystem"""

        source = discord.PCMVolumeTransformer(discord.FFmpegPCMAudio(query))
        ctx.voice_client.play(source, after=lambda e: print('Player error: %s' % e) if e else None)

        await ctx.send('Now playing: {}'.format(query))

#Downloads then plays youtube video
    @commands.command()
    async def yt(self, ctx, *, url):
        """Plays from a url (almost anything youtube_dl supports)"""

        async with ctx.typing():
            player = await YTDLSource.from_url(url, loop=self.bot.loop)
            ctx.voice_client.play(player, after=lambda e: print('Player error: %s' % e) if e else None)

        await ctx.send('Now playing: {}'.format(player.title))

#streams url / plays it
    @commands.command()
    async def stream(self, ctx, *, url):
        """Streams from a url (same as yt, but doesn't predownload)"""

        async with ctx.typing():
            player = await YTDLSource.from_url(url, loop=self.bot.loop, stream=True)
            ctx.voice_client.play(player, after=lambda e: print('Player error: %s' % e) if e else None)

        await ctx.send('Now playing: {}'.format(player.title))

#Change Volume height
    @commands.command()
    async def volume(self, ctx, volume: int):
        """Changes the player's volume"""

        if ctx.voice_client is None:
            return await ctx.send("Not connected to a voice channel.")

        ctx.voice_client.source.volume = volume / 100
        await ctx.send("Changed volume to {}%".format(volume))

#Stops music & disconnects
    @commands.command()
    async def stop(self, ctx):
        """Stops and disconnects the bot from voice"""

        await ctx.voice_client.disconnect()

    @play.before_invoke
    @yt.before_invoke
    @stream.before_invoke
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
        await bot.change_presence(status=discord.Status.idle, activity=discord.Game('Watch Dogs Legion'))
        print('***********************************************************')
        print('__________                .__                   ')
        print('\______   \_____     ____ |  |   ____ ___.__.   ')
        print(' |    |  _/\__  \   / ___\|  | _/ __ <   |  |   ')
        print(' |    |   \ / __ \_/ /_/  >  |_\  ___/\___  |   ')
        print(' |______  /(____  /\___  /|____/\___  > ____|   ')
        print('        \/      \//_____/           \/\/ online!')
        print('                                                ')
        print('***********************************************************')

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

    #ping to bot server 
    @bot.command()
    async def ping(ctx):
        await ctx.send(f'ping: {round(bot.latency * 1000)}ms')
        
        
    #Runs Shutdown script
    @bot.command()
    @commands.check(is_it_me)
    async def shutdown(ctx):
        await ctx.send(f'Shutting down Bagley bot server')
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
        await ctx.send('Getting IP')
        hostname = socket.gethostbyaddr(socket.gethostname())
        ip_address = socket.gethostbyname(socket.gethostname())
        print(f"Hostname: {hostname}")
        print(f"IP: {ip_address}")
        await ctx.author.send(f'Hostname: {hostname}')
        await ctx.author.send(f'IP: {ip_address}')
        #subprocess.call([r'E:\DiscordBot\scripts\ip.bat'])
    
    #IP Info
    @bot.command()
    async def ipinfo(ctx, ipadd):
        handler = ipinfo.getHandler(ipinfoapi_token)
        details = handler.getDetails(ipadd)
        await ctx.author.send("Searching info on: "+ipadd)
        await ctx.author.send("Here is what we found:")
        await ctx.author.send(details.all)
        #Abstract API 
        response = requests.get(f"https://ipgeolocation.abstractapi.com/v1/?api_key={abs_geo}&ip_address={ipadd}")
        await ctx.author.send("Searching info using AbstractAPI: "+ipadd)
        print(response.status_code)
        await ctx.author.send("Here is what we found:")
        info = response.content
        print(response.content)
        await ctx.author.send(info)
        
    #wifi near me (near Bagley)
    @bot.command()
    @commands.check(is_it_me)
    async def wifi(ctx): 
        await ctx.author.send(ssids)
        
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
        await ctx.send(f'Bagley found: '+wolf_res)

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
        await ctx.author.send("Here is what we found:")
        print(response.content)
        info = reponse.content
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
        file_path = open(path+file_name)
        await ctx.author.send(file_path.read())
     
    #turn url to ip
    @bot.command()
    async def url2ip(ctx, website):
        ip_add = gethostbyname(website)
        await ctx.author.send(f"""The IP for the {website} is: {ip_add}""")
    
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

        # save the discovered subdomains into a file
        with open("discovered_subdomains.txt", "w") as f:
            for subdomain in discovered_subdomains:
                print(subdomain, file=f)
    

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
