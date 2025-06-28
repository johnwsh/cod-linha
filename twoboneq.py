def lineEncode(message: str):

    levels = []

    positive = True

    for i in range(0, int(len(message)-1), 2):

        nextBits = message[i:i+2]

        match nextBits:
            case "00":
                if positive:
                    levels.append(1)
                    positive = True
                else:
                    levels.append(-1)
                    positive = False
            case "01":
                if positive:
                    levels.append(3)
                    positive = True
                else:
                    levels.append(-3)
                    positive = False
            case "10":
                if positive:
                    levels.append(-1)
                    positive = False
                else:
                    levels.append(1)
                    positive = True
            case "11":
                if positive:
                    levels.append(-3)
                    positive = False
                else:
                    levels.append(3)
                    positive = True
            case _:
                raise ValueError("Invalid bit value")
            
    return levels
            
def lineDecode(levels: list[int]):

    message = ""

    positive = True

    for level in levels:

        if level == 1:
            if positive:
                message += "00"
            else:
                message += "10"
            positive = True
        elif level == -1:
            if positive:
                message += "10"
            else:
                message += "00"
            positive = False
        elif level == 3:
            if positive:
                message += "01"
            else:
                message += "11"
            positive = True
        elif level == -3:
            if positive:
                message += "11"
            else:
                message += "01"
            positive = False
        else:
            raise ValueError("Invalid level value")

    return message