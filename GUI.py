import PySimpleGUI as sg


def mprint(*args, **kwargs):
    window['-ML1-'+sg.WRITE_ONLY_KEY].print(*args, **kwargs)
# GUI definittion # 
print = mprint

layout = [
    [sg.Text("Demonstration")],
    [sg.MLine(key='-ML1-'+ sg.WRITE_ONLY_KEY, size=(60,20))],
    [sg.Button('Go'), sg.Button('Exit')]
]

window = sg.Window("Just a window", layout, finalize=True)
print(1,2,3,4,end='', text_color='red', background_color='yellow')
print('\n', end='')
print(1,2,3,4,text_color='white', background_color='green')
counter = 0

while True:
    event, values = window.read(timeout=100)
    if event == (sg.WINDOW_CLOSED, 'Exit'):
        break
    
    elif event == 'Go':
        print(event, values)
    print(counter)
    counter+=1

        

window.close()