import discord
from discord.ext import commands
import logging
from dotenv import load_dotenv
import os

import aiohttp
import io
from PIL import Image
import imagehash

import json

# Run pip install -r .\requirements.txt to install the required packages

load_dotenv()
token = os.getenv('DISCORD_TOKEN')

handler = logging.FileHandler(filename='discord.log', encoding='utf-8', mode='w')
intents = discord.Intents.default()
intents.message_content = True
intents.members = True

bot = commands.Bot(command_prefix='!', intents=intents)




# Sets up malicious hash list
malicious_hashes = set()

for filename in os.listdir("malicious_images"):
    img = Image.open(os.path.join("malicious_images", filename))
    malicious_hashes.add(imagehash.phash(img))


session = None

# What the bot does when it is "ready"
@bot.event
async def on_ready():

    global session
    session = aiohttp.ClientSession()

    print(f"ready for action, {bot.user.name}")

# What the bot does when a member joins the server
@bot.event
async def on_member_join(member):
    #await member.send(f"Welcome to the server, {member.name}!")
    if member.id in black_list:
        await member.send("You are on the blacklist and will be banned from the server.")
        await member.ban(reason="User is on the blacklist.")
        print("Banned user: " + member.name + " (ID: " + str(member.id) + ")")

# What the bot does when a message is sent
@bot.event
async def on_message(message):
    if message.author == bot.user:
        return
    # Check if the message contains an image
    for attachment in message.attachments:
        await message.channel.send(f"Image sent by {message.author.name} (ID: {message.author.id})")
        if not (
            attachment.content_type and 
            attachment.content_type.startswith("image")
        ):
            continue
        try:
            async with session.get(attachment.url) as response:
                if response.status != 200:
                    continue

                data = await response.read()

            img = Image.open(io.BytesIO(data))

            uploaded_hash = imagehash.phash(img)

            # Compare against known malicious hashes
            for bad_hash in malicious_hashes:
                # Gets delta between 2 images
                distance = uploaded_hash - bad_hash
                
                if distance <= 5:
                    await message.delete()
                    
                    # Bans the user
                    try:
                        await message.author.ban(reason="Sent a known malicious image.")
                        await message.channel.send(f"{message.author.mention} has been banned for sending a known malicious image.")

                        print(
                            f"Banned user: {message.author.name} "
                            f"(ID: {message.author.id}) "
                            f"for sending a known malicious image."
                        )

                    except discord.Forbidden:
                        print(f"Failed to ban user: {message.author.name} (ID: {message.author.id}) - insufficient permissions.")
                    except discord.HTTPException as e:
                        print(f"Failed to ban user: {message.author.name} (ID: {message.author.id}) - HTTPException: {e}")

                    return
        except Exception as e:
            print(f"Error processing image from {message.author.name} (ID: {message.author.id}): {e}")
                
    # Lets the bot process commands after checking for malicious images
    await bot.process_commands(message)


# Loads the list of known malicious users
black_list = []

BLACKLIST_FILE = "blacklist.json"

def load_blacklist():
    try: 
        with open(BLACKLIST_FILE, "r") as f:
            return set(json.load(f))
    except:
        return set()
    
def save_blacklist():
    with open(BLACKLIST_FILE, "w") as f:
        json.dump(list(black_list), f)

black_list = load_blacklist()


# A command that will add a specified user to the blacklist of known malicious users
@bot.command()
async def addToList(ctx, member: discord.Member):
    # Check if the member is already in the blacklist
    if member.id in black_list:
        await ctx.send(f"{member.name} is already in the blacklist.")
        return
    
    # Add the member to the blacklist
    black_list.add(member.id)
    save_blacklist()

    await ctx.send(
        f"Added {member.mention} to the list.\n" 
        f"Discord UID: `{member.id}`"
    )

    # Bans the user from the server


#runs the bot
bot.run(token, log_handler=handler, log_level=logging.DEBUG)

