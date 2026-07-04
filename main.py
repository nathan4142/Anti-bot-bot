import discord
from discord.ext import commands
import logging
from dotenv import load_dotenv
import os

import aiohttp
import io
from PIL import Image
from PIL import ImageOps
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

# Converts image into multiple different hashes for comparison
def get_hashes(img):
    # Normalize the image
    img = img.convert("RGB")
    img.thumbnail((512, 512))
    img = ImageOps.autocontrast(img)
    return {
        "phash": imagehash.phash(img),
        "dhash": imagehash.dhash(img),
        "ahash": imagehash.average_hash(img),
        "whash": imagehash.whash(img),
        "grayscale": imagehash.phash(img.convert("L")) 
    }

# Sets up malicious hash list
# maybe make a set()
malicious_hashes = []

for filename in os.listdir("malicious_images"):
    img = Image.open(os.path.join("malicious_images", filename))

    malicious_hashes.append({
        "filename": filename,
        "hashes": get_hashes(img)
    })

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
        await member.kick(reason="User is on the blacklist.")
        #await member.ban(reason="User is on the blacklist.")
        print("Banned user: " + member.name + " (ID: " + str(member.id) + ")")

# What the bot does when a message is sent
@bot.event
async def on_message(message):
    if message.author == bot.user:
        return
    # Check if the message contains an image
    for attachment in message.attachments:
        # DEBUG await message.channel.send(f"Image sent by {message.author.name} (ID: {message.author.id})")
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



            #uploaded_hash = imagehash.phash(img)
            # Gets hashes and compares against known malicious hashes
            uploaded_hashes = get_hashes(img)

            for bad_hash in malicious_hashes:
                matches = 0
                if uploaded_hashes["phash"] - bad_hash["hashes"]["phash"] <= 5:
                    matches += 1

                if uploaded_hashes["dhash"] - bad_hash["hashes"]["dhash"] <= 8:
                    matches += 1
                
                if uploaded_hashes["ahash"] - bad_hash["hashes"]["ahash"] <= 5:
                    matches += 1
                
                if uploaded_hashes["whash"] - bad_hash["hashes"]["whash"] <= 8:
                    matches += 1

                if uploaded_hashes["grayscale"] - bad_hash["hashes"]["grayscale"] <= 5:
                    matches += 1

                if matches >= 2: # Threshold for similarity
                    await message.delete()
                    
                    # Bans the user
                    try:
                        
                        await message.channel.send(f"{message.author.mention} has sent an image that matches a known malicious image hash.")

                        # Need to create a role called "anti-bot-suspect" in the server for this to work
                        await message.author.add_roles(discord.utils.get(message.guild.roles, name="anti-bot-suspect"))

                        # Replace this with the channel ID of the channel called "anti-bot-appeals"
                        channel_id = 1523020697679691876
                        appeals_channel = bot.get_channel(channel_id)

                        # Creates a thread in the appeals channel
                        starter_message = await appeals_channel.send(f"Case: {message.author.mention}")

                        thread = await starter_message.create_thread(
                            name=f"Appeal thread for {message.author.name}",
                            auto_archive_duration=60,  # Auto-archive after 60 minutes of inactivity
                        )
                        await thread.send(f"{message.author.mention}, you have been flagged for sending a potentially malicious image. If you believe this is a mistake, a staff member will review your case.")
                        # Sends the flagged image for review by a moderator
                        await thread.send("Flagged image:")
                        await thread.send(file=discord.File(io.BytesIO(data), filename=attachment.filename))



                    except discord.Forbidden:
                        print(f"Failed to ban user: {message.author.name} (ID: {message.author.id}) - insufficient permissions.")
                    except discord.HTTPException as e:
                        print(f"Failed to ban user: {message.author.name} (ID: {message.author.id}) - HTTPException: {e}")

                    return
        except Exception as e:
            print(f"Error processing image from {message.author.name} (ID: {message.author.id}): {e}")
                
    # Lets the bot process commands after checking for malicious images
    await bot.process_commands(message)





# A command that will add a specified user to the blacklist of known malicious users
@bot.command()
@commands.has_any_role("Admin", "Moderator")
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

@bot.command()
@commands.has_any_role("Admin", "Moderator")
async def testUserJoin(ctx, member: discord.Member):
    if member.id in black_list:
        await member.send("You are on the blacklist and will be banned from the server.")
        await member.kick(reason="User is on the blacklist.")
        #await member.ban(reason="User is on the blacklist.")
        print("Banned user: " + member.name + " (ID: " + str(member.id) + ")")


@bot.command()
@commands.has_any_role("Admin", "Moderator")
async def disconnect(ctx):
    global session
    if session:
        await session.close()
        session = None
        await ctx.send("Client session closed.")
    else:
        await ctx.send("No active client session to close.")


@bot.command()
@commands.has_any_role("Admin", "Moderator")
async def readBlackList(ctx):
    if black_list:
        blacklist_str = "\n".join(str(uid) for uid in black_list)
        await ctx.send(f"Current Blacklist:\n{blacklist_str}")
    else:
        await ctx.send("The blacklist is currently empty.")

@bot.command()
@commands.has_any_role("Admin", "Moderator")
async def guilty(ctx, member: discord.Member):
    black_list.add(member.id)
    save_blacklist()

    await member.kick(reason="Sent a known malicious image.")
    #await member.ban(reason="Sent a known malicious image.")

@bot.command()
@commands.has_any_role("Admin", "Moderator")
async def innocent(ctx, member: discord.Member):
    await member.remove_roles(discord.utils.get(member.guild.roles, name="anti-bot-suspect"))


#runs the bot
bot.run(token, log_handler=handler, log_level=logging.DEBUG)

