from twoboneq import lineEncode


def main():
    seq = "0011011001"

    encoded_levels = lineEncode(seq)
    
    print("Lista de Níveis (2B1Q):", encoded_levels)

main()