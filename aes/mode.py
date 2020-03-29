# Programmed by TH3_S1LENC3
# Contains all code for getting and writing mode

supportedModes = ["CBC", "GCM"]

def get_mode():
    filename = "AES_MODE.txt"
    mode = ""
    try:
        file = open(filename,"r")
        mode = file.read()
        print(mode)
        for supportedMode in supportedModes:
            print(supportedMode)
            if supportedMode != mode:
                raise ValueError("Mode in " + filename + " not supported!")
        file.close()
    except IOError:
        print("Failed to open " + filename + ".")
    except ValueError as error:
        print(error)
    return mode

def write_mode(filename):
    filename = filename
    try:
        file = open(filename,"w")
        file.write(mode)
        file.close()
    except IOError:
        print ("Failed to open " + filename + ".")
        file.close()
    finally:
        print("Mode Written Successfully") # For Debugging
