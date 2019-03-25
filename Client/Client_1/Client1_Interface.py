from tkinter import *
from tkinter import PhotoImage
from tkinter.filedialog import *


b = "white"
f = "black"

# ///// interface 1 \\\\\
def homepage():
    r = Tk()
    r.title("TPE Client Page d'accueil")
    r.geometry("350x250")
    r["bg"] = b
    r.resizable(False, False)
    c = Canvas(r, width=354, height=254, bg=b, bd=0)

    c.place(x=-2, y=-2)
    c.create_text(175, 50, fill=f, font="courier 20", text="Data Splitting:\n   ClientSide")
    b1 = Button(r, text="     START     ", bg=b, fg=f, command=lambda: connexionserveur())
    b1.place(x=50, y=120)
    b2 = Button(r, text="     SETTINGS     ", bg=b, fg=f)
    b2.place(x=200, y=120)
    b3 = Button(r, text="     QUIT     ", bg=b, fg=f, command = r.destroy)
    b3.place(x=125, y=170)

    r.mainloop()

# ///// interface 2 \\\\\
def selection():
    r = Tk()
    r.geometry("350x250")
    r.resizable(False, False)

    #canvas = Canvas(r, width=354, height=254, bg="white")
    filepath = askopenfilename(title="Ouvrir une image", filetypes=[("png files", ".png"), ("all files", ".*")])
    return filepath
    #photo = PhotoImage(file=filepath)
    #canvas.create_image((177 - (photo.width() / 2)), (127 - (photo.height() / 2)), anchor=NW, image=photo)

    #canvas.place(x=-2, y=-2)
    r.mainloop()


# ///// interface 3 \\\\\
def connexionserveur():
    r = Tk()
    r.title("TPE Connexion Serveurs")
    r.geometry("350x250")
    r["bg"] = b
    r.resizable(False, False)
    c = Canvas(r, width=354, height=254, bg=b, bd=0)
    c.create_line(177,100,177,250,fill=f)
    c.create_text(175, 50, fill=f, font="courier 20", text="Data Splitting:\nconnexion serveurs")
    c.create_text(88, 130, fill=f, font="courier 15", text="Serveur I")
    c.create_text(88, 180, fill=f, font="courier 10", text="IP: ###.##.###.#\nPort: ###.##.###.#")
    c.create_text(266, 130, fill=f, font="courier 15", text="Serveur II")
    c.create_text(266, 180, fill=f, font="courier 10", text="IP: ###.##.###.#\nPort: ###.##.###.#")

    c.place(x=-2, y=-2)
    r.mainloop()

# ///// interface 4 \\\\\
def attenteinteraction():
    r = Tk()
    r.title("TPE Attente d'Interaction")
    r.geometry("350x250+65+35")
    r.resizable(False, False)

    can = Canvas(r, width=354, height=254, bg="white")
    can.place(x=-2, y=-2)
    can.create_text(175, 30, fill=f, font="courier 15", text="En Attente d'Interaction")
    photo = PhotoImage(file="wait.gif")
    can.create_image(113,80,anchor="nw", image=photo, tag="photo")
    global i
    i = 0
    def update(delay=50):
        global i
        i += 1
        if i == 16:
            i = 0
        photo.configure(format="gif -index " + str(i))
        r.after(delay, update)
    update()
    r.mainloop()

# ///// interface 4 \\\\\
def cryptage():
    r = Tk()
    r.title("Cryptage")
    r.geometry("350x250")
    r.resizable(False, False)

    photo = PhotoImage(file="intCDC.png")

    canvas = Canvas (r, width=354, height=254, bg="white")
    canvas.create_image(35, 50, anchor=NW, image=photo)
    canvas.create_text(175, 30, fill="black", font="courier 15", text="Cryptage en cours")

    canvas.place(x=-2, y=-2)
    r.mainloop()

# ///// interface 5 \\\\\
def decryptage():
    r = Tk()
    r.geometry("350x250")
    r.resizable(False, False)
    r.title("Decryptage")

    photo = PhotoImage(file="intCDC.png")

    canvas = Canvas (r, width=554, height=254, background="white")
    canvas.create_image(35, 50, anchor=NW, image=photo)
    canvas.create_text(175, 30, fill="black", font="courier 15", text="Decryptage en cours")

    canvas.place(x=-2,y=-2)
    r.mainloop()

# ///// interface 6 \\\\\
def envoi():
    r = Tk()
    r.geometry("350x250")
    r.resizable(False, False)

    photo = PhotoImage (file="envoi.png")

    c = Canvas (r, width=354, height=254, background="white")
    c.create_line(177, 100, 177, 250, fill="black")
    c.create_text(88, 130, fill="black", font="courier 15", text="Serveur I")
    c.create_text(266, 130, fill="black", font="courier 15", text="Serveur II")
    c.create_image (38, 160, anchor=NW, image=photo)
    c.create_image (216, 160, anchor=NW, image=photo)
    c.create_line(400, 150, 400, 600)
    c.create_text(177, 50, fill="black", font="courier 15", text="Envoi en Cours")

    c.place(x=-2, y=-2)
    r.mainloop()

# ///// interface 9 \\\\\
def reception():
    r = Tk()
    r.geometry("350x250")
    r.resizable(0, 0)
    r.title("TPE Reception")

    photo = PhotoImage(file="chargement S.png")

    c = Canvas(r, width=354, height=254, background="white")
    c.create_line(177, 100, 177, 250, fill="black")
    c.create_text(88, 130, fill="black", font="courier 15", text="Serveur I")
    c.create_text(266, 130, fill="black", font="courier 15", text="Serveur II")
    c.create_image(38, 160, anchor=NW, image=photo)
    c.create_image(216, 160, anchor=NW, image=photo)
    c.create_line(400, 150, 400, 600)
    c.create_text(177, 50, fill="black", font="courier 15", text="Reception en Cours")

    c.place(x=-2, y=-2)
    r.mainloop()

# ///// interface 8 \\\\\
def split():
    r = Tk()
    r.title("TPE Split")
    r.geometry("350x250")
    r.resizable(False, False)

    photosd = PhotoImage(file="file sd.png")
    photosb = PhotoImage(file="file sb.png")

    canvas = Canvas(r, width=354, height=254, background="white")
    canvas.create_image(127, 70, anchor=NW, image=photosb)
    canvas.create_image(22, 157, anchor=NW, image=photosd)
    canvas.create_image(257, 157, anchor=NW, image=photosd)
    canvas.create_text(177, 30, fill="black", font="courier 15", text="Split")
    canvas.create_line(177, 142, 97, 170, fill="black")
    canvas.create_line(177, 142, 257, 170, fill="black")

    canvas.place(x=-2, y=-2)
    r.mainloop()

# ///// interface 10 \\\\\
def rassemble():
    r = Tk()
    r.title("Rassemblement")
    r.geometry("350x250")
    r.resizable(False, False)

    photosd = PhotoImage(file="file sd.png")
    photosb = PhotoImage(file="file sb.png")

    canvas = Canvas(r, width=354, height=254, background="white")
    canvas.create_image(127, 157, anchor=NW, image=photosb)
    canvas.create_image(22, 70, anchor=NW, image=photosd)
    canvas.create_image(257, 70, anchor=NW, image=photosd)
    canvas.create_text(177, 30, fill="black", font="courier 15", text="Rassemblement")
    canvas.create_line(60, 140, 125, 170, fill="black")
    canvas.create_line(300, 140, 225, 170, fill="black")

    canvas.place(x=-2, y=-2)
    r.mainloop()

# ///// interface 11 \\\\\
def DH_init():  # Alternate img
    r = Tk()
    r.title("DH initialisation")
    r.geometry("350x250")
    r.resizable(False, False)

    tick = PhotoImage(file="tickmodif.png")
    wait = PhotoImage(file="waitmodif.gif")

    canvas = Canvas(r, width=354, height=254, background="white")
    canvas.create_text(177, 30, fill="black", font="courier 15", text="DH initialisation")
    canvas.create_text(120, 80, fill="black", font="courier 15", text="Génération clé S1 :")
    canvas.create_image(230, 55, anchor=NW, image=tick)
    canvas.create_image(230, 55, anchor=NW, image=wait)
    canvas.create_text(120, 140, fill="black", font="courier 15", text="Génération clé S2 :")
    canvas.create_image(230, 115, anchor=NW, image=tick)
    canvas.create_image(230, 115, anchor=NW, image=wait)
    canvas.create_text(120, 200, fill="black", font="courier 15", text="Génération clé C2 :")
    canvas.create_image(230, 175, anchor=NW, image=tick)
    canvas.create_image(230, 175, anchor=NW, image=wait)
    global i
    i = 0
    def update(delay=50):
        global i
        i += 1
        if i == 16:
            i = 0
        wait.configure(format="gif -index " + str(i))
        r.after(delay, update)

    update()
    canvas.place(x=-2, y=-2)
    r.mainloop()

def Key_init(): # Alternate img
    r = Tk()
    r.title("Clés initialisation")
    r.geometry("350x250")
    r.resizable(False, False)

    tick = PhotoImage(file="tickmodif25.png")
    wait = PhotoImage(file="waitmodif25.gif")

    canvas = Canvas(r, width=354, height=254, background="white")
    canvas.create_text(177, 30, fill="black", font="courier 15", text="Initialisation des clés")
    canvas.create_text(65, 90, fill="black", font="courier 12", text="Clé gen S1 :")
    canvas.create_image(130, 77, anchor=NW, image=tick)
    canvas.create_image(130, 77, anchor=NW, image=wait)
    canvas.create_text(65, 140, fill="black", font="courier 12", text="Clé gen S2 :")
    canvas.create_image(130, 127, anchor=NW, image=tick)
    canvas.create_image(130, 127, anchor=NW, image=wait)
    canvas.create_text(65, 190, fill="black", font="courier 12", text="Clé gen C2 :")
    canvas.create_image(130, 177, anchor=NW, image=tick)
    canvas.create_image(130, 177, anchor=NW, image=wait)

    canvas.create_text(245, 90, fill="black", font="courier 12", text="Envoi clé S1 :")
    canvas.create_image(320, 77, anchor=NW, image=tick)
    canvas.create_image(320, 77, anchor=NW, image=wait)
    canvas.create_text(245, 140, fill="black", font="courier 12", text="Envoi clé S2 :")
    canvas.create_image(320, 127, anchor=NW, image=tick)
    canvas.create_image(320, 127, anchor=NW, image=wait)
    canvas.create_text(245, 190, fill="black", font="courier 12", text="Envoi clé C2 :")
    canvas.create_image(320, 177, anchor=NW, image=tick)
    canvas.create_image(320, 177, anchor=NW, image=wait)
    global i
    i = 0
    def update(delay=50):
        global i
        i += 1
        if i == 16:
            i = 0
        wait.configure(format="gif -index " + str(i))
        r.after(delay, update)
    update()
    canvas.place(x=-2, y=-2)
    r.mainloop()
