from AES_Functions import *
import os

common_key = b''
aes_operation_mode = ''
file_to_send = ''


def send_file_content_to_node_b(write_head, given_key):
    with open(file_to_send, 'rb') as fd:
        content = fd.read()
        # if you work only with text files, simply uncomment the code line under this comment:
        # print(content, flush=True)
        if aes_operation_mode == 'ECB':
            encrypted_content = list(ecb_encryption(given_key, content))
        else:
            encrypted_content = list(cfb_encryption(given_key, content))
        for block in encrypted_content:
            os.write(write_head, block)
        os.write(write_head, b'\0')


if __name__ == '__main__':
    # open the communication channels with Key Manager and node B.
    km_to_a = os.open("KM_to_A", os.O_RDONLY)
    a_to_km = os.open('A_to_KM', os.O_WRONLY)
    a_to_b = os.open("A_to_B", os.O_WRONLY)
    b_to_a = os.open("B_to_A", os.O_RDONLY)

    # receive public key from Key Manager and send it to node B.
    common_key = os.read(km_to_a, 16)
    os.write(a_to_b, common_key)

    # read from console the AES operation mode and send it to both Key Manager and node B.
    aes_operation_mode = input("Specify an AES operation mode: ").upper()
    os.write(a_to_km, aes_operation_mode.encode())
    os.write(a_to_b, aes_operation_mode.encode())

    # receive the encrypted private key from Key Manager, send it to B and decrypt it.
    encrypted_key = os.read(km_to_a, 16)
    aes_operation_mode_key = ecb_block_decryption(common_key, encrypted_key)
    os.write(a_to_b, encrypted_key)

    # receive from node B a message to see whether he is ready to communicate.
    is_b_ready = bool(os.read(b_to_a, 1).decode())

    # print data in order to check that communication between the members is working correctly.
    print(f'Public key: {common_key}\n')
    print(f'AES operation mode: {aes_operation_mode}\n')
    print(f'Encrypted private key: {encrypted_key}\n')
    print(f'Private key: {aes_operation_mode_key}\n')

    # close all communication channels that are no longer used.
    os.close(a_to_km)
    os.close(km_to_a)
    os.close(b_to_a)

    # check if node B is ready; if yes, start sending the encrypted contents of a given file.
    if is_b_ready:
        print("Node B is ready!\n")
        file_to_send = input("Specify a filename: ")
        send_file_content_to_node_b(a_to_b, aes_operation_mode_key)
        os.close(a_to_b)
    else:
        raise Exception("Node B is not ready!")
