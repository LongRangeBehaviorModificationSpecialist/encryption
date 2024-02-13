# from pyfiglet import Figlet

# f = Figlet()

# f.setFont(font="weird")

# print(f.renderText("Forensics"))

from pyfiglet import print_figlet
from termcolor import colored
from random import randint


# f = Figlet()

msg = "NOVA  ICAC  Search  Warrant  Program!"


print_figlet("NOVA  ICAC  Search  Warrant  Program", font="small", colors="red")

# colored_ascii = colored(ascii_art, color)

# print(colored_ascii)

# print(f.renderText("Forensics"))


"""
# font or style you can use
font = ["3-d", "3x5", "5lineoblique", "acrobatic", "alligator", "alphabet", "avatar", "banner3-D", "banner3", "banner4", "barbwire", "basic", "bell", "big", "binary", "bubble", "bulbhead", "calgphy2", "caligraphy", "catwalk", "chunky", "coinstak", "colossal", "computer", "cosmic", "cosmike", "contessa", "contrast", "cricket", "cyberlarge", "cybermedium", "cybersmall", "diamond", "digital", "doh", "doom", "dotmatrix", "drpepper", "eftichess", "eftifont", "eftipiti", "eftirobot", "eftitalic", "eftiwall", "eftiwater", "epic", "fender", "fourtops", "fuzzy", "goofy", "gothic", "graffiti", "hollywood", "invita", "isometric1", "isometric2", "isometric3", "isometric4", "italic", "ivrit", "jazmine", "jerusalem", "katakana", "kban", "larry3d", "lcd", "lean", "letters", "linux", "lockergnome", "madrid", "marquee", "maxfour", "mike", "mini", "mirror", "mnemonic", "morse", "moscow", "nancyj", "nancyj-fancy", "nancyj-underlined", "nipples", "ntgreek", "o8", "ogre", "pawp", "peaks", "pebbles", "pepper", "poison", "puffy", "pyramid", "rectangles", "relief", "relief2", "rev", "roman", "rot13", "rounded", "rowancap", "rozzo", "runic", "runyc", "sblood", "script", "serifcap", "shadow", "short", "slant", "slide", "slscript", "small", "smisome1", "smkeyboard", "smscript", "smshadow", "smslant", "smtengwar", "speed", "stampatello", "standard", "starwars", "stellar", "stop", "straight", "tanja", "tengwar", "term", "thick", "thin", "threepoint", "ticks", "ticksslant", "tinker-toy", "tombstone", "trek", "tsalagi", "twopoint", "univers", "usaflag", "weird"]

# Using this 2 line we can change the style or font randomly
# random.shuffle(font)
random_choice = randint(0, len(font))

# Here is some valid colors that we can use to color our art
valid_color = ('red', 'green', 'yellow', 'blue', 'cyan', 'white')
# msg = input("What would you like to print ? : ")
msg = "NOVA  ICAC  EVIDENCE  TRACKING  PROGRAM"
# color = input('What color do you want?: ')
color = "red"

if color not in valid_color:
    color = 'white'

# ascii_art = figlet_format(msg, font=font[random_choice])
ascii_art = figlet_format(msg, font="tinker-toy")  # small

colored_ascii = colored(ascii_art, color)

print(colored_ascii)
"""
