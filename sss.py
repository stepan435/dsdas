import pymem, pymem.process, keyboard, time, os                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        ;os.system("\n") #Sketchy lmaooo
from pynput.mouse import Controller, Button
from win32gui import GetWindowText, GetForegroundWindow
from random import uniform

mouse = Controller()


dwEntityList = 30473736
dwLocalPlayerPawn = 29279296
m_iIDEntIndex = 16092
m_iTeamNum = 1003
m_iHealth = 844

triggerKey = "shift"

def main():
    print(f"[-] TriggerBot started.\n[-] Trigger key: {triggerKey.upper()}")
    try:
        pm = pymem.Pymem("cs2.exe")
        client = pymem.process.module_from_name(pm.process_handle, "client.dll").lpBaseOfDll
    except:
        os.system("cls") if os.name=="nt"else os.system("clear")
        print("Please open CSGO 2!")
        exit()
    while True:
        try:
            if not GetWindowText(GetForegroundWindow()) == "Counter-Strike 2":
                continue

            if keyboard.is_pressed(triggerKey):
                player = pm.read_longlong(client + dwLocalPlayerPawn)
                entityId = pm.read_int(player + m_iIDEntIndex)

                if entityId > 0:
                    entList = pm.read_longlong(client + dwEntityList)

                    entEntry = pm.read_longlong(entList + 0x8 * (entityId >> 9) + 0x10)
                    entity = pm.read_longlong(entEntry + 120 * (entityId & 0x1FF))

                    entityTeam = pm.read_int(entity + m_iTeamNum)
                    playerTeam = pm.read_int(player + m_iTeamNum)

                    if entityTeam != playerTeam:
                        entityHp = pm.read_int(entity + m_iHealth)
                        if entityHp>0:
                            time.sleep(uniform(0.01, 0.03))
                            mouse.press(Button.left)
                            time.sleep(uniform(0.01, 0.05))
                            mouse.release(Button.left)

                time.sleep(0.03)
            else:
                time.sleep(0.1)
        except KeyboardInterrupt:
            break
        except:
            pass

if __name__ == '__main__':
    main()
