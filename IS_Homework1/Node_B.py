import os
from AES_Functions import *
import magic

common_key = b''
aes_operation_mode = ''


def process_file_content_from_node_a(read_head, given_key):
    encrypted_message = b''
    encrypted_block = os.read(read_head, 16)
    cnt = 0
    while encrypted_block != b'\0':
        # if you work only with text files, simply uncomment the code line under this comment:
        # print(f"Block {cnt + 1}: {encrypted_block}\n")
        encrypted_message += encrypted_block
        cnt += 1
        encrypted_block = os.read(read_head, 16)

    # if you work only with text files, simply uncomment the code line under this comment:
    # print(encrypted_message, flush=True)

    if aes_operation_mode == 'ECB':
        decrypted_blocks = list(ecb_decryption(given_key, encrypted_message))
    else:
        decrypted_blocks = list(cfb_decryption(given_key, encrypted_message))

    decrypted_message = b''
    for index, block in enumerate(decrypted_blocks):
        # if you work only with text files, simply uncomment the code line under this comment:
        # print(f"Block {index+1}: {block}\n")
        decrypted_message += block

    # if you work only with text files, simply uncomment the code line under this comment:
    # print(decrypted_message, flush=True)
    with open('result', 'wb') as fd:
        for block in decrypted_blocks:
            fd.write(block)

    # determine the correct mime type of the created 'result' file and assign to it the correct extension.
    # if you work only with text files, simply comment the code section under this comment:
    mimetype = magic.from_file('result', mime=True)
    if mimetype == 'image/bmp':
        os.rename('result', 'result.bmp')
    elif mimetype == 'application/octet-stream':
        os.rename('result', 'result.txt')


if __name__ == '__main__':
    # open the communication channels with node A.
    a_to_b = os.open("A_to_B", os.O_RDONLY)
    b_to_a = os.open("B_to_A", os.O_WRONLY)

    # receive the public key, the AES operation mode and the encrypted private key from node A.
    common_key = os.read(a_to_b, 16)
    aes_operation_mode = os.read(a_to_b, 3).decode()
    encrypted_key = os.read(a_to_b, 16)

    # decrypt the encrypted private key.
    aes_operation_mode_key = ecb_block_decryption(common_key, encrypted_key)

    # print data in order to check that communication between the members is working correctly.
    print(f'Public key: {common_key}\n')
    print(f'AES operation mode: {aes_operation_mode}\n')
    print(f'Encrypted private key: {encrypted_key}\n')
    print(f'Private key: {aes_operation_mode_key}\n')

    # check if private key was sent correctly; if yes, notify node A correspondingly and begin
    # to receive and manage the encrypted blocks sent by node A.
    if len(aes_operation_mode_key) == 16:
        os.write(b_to_a, b'1')
        os.close(b_to_a)
        process_file_content_from_node_a(a_to_b, aes_operation_mode_key)
        os.close(a_to_b)
    else:
        os.write(b_to_a, b'0')
        raise Exception("Cipher key compromised!")
