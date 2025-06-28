import criptAndBinary
import twoboneq

def main():
    message = b"Hello, World!"
    password = b"my_secret_password"

    encripted_message = criptAndBinary.encryptMessage(message, password)
    binarized_message = criptAndBinary.binarize(encripted_message)
    print(f"Binarized message: {binarized_message}")

    encoded_levels = twoboneq.lineEncode(binarized_message)

    print(f"Encoded levels: {encoded_levels}")

    decoded_levels = twoboneq.lineDecode(encoded_levels)
    print(f"Decoded levels: {decoded_levels}")
    debinarized_message = criptAndBinary.debinarize(decoded_levels)
    decrypted_message = criptAndBinary.decryptMessage(debinarized_message, password)
    print(f"Decrypted message: {decrypted_message}")

main()

