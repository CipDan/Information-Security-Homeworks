from AES_Functions import *
import os


def give_key(encryption_type):
    if encryption_type == "ECB":
        return os.urandom(16)
    elif encryption_type == "CFB":
        return os.urandom(16)
    else:
        raise Exception('Unknown encryption type!')


def create_comm_channels():
    if not os.path.exists("A_to_KM"):
        os.mkfifo("A_to_KM")
    if not os.path.exists("KM_to_A"):
        os.mkfifo("KM_to_A")
    if not os.path.exists("A_to_B"):
        os.mkfifo("A_to_B")
    if not os.path.exists("B_to_A"):
        os.mkfifo("B_to_A")


if __name__ == '__main__':
    # create communication channels.
    create_comm_channels()

    # open the communication channels with node A.
    km_to_a = os.open('KM_to_A', os.O_WRONLY)
    a_to_km = os.open('A_to_KM', os.O_RDONLY)

    # generate public key and send it to node A.
    common_key = os.urandom(16)
    os.write(km_to_a, common_key)

    # receive the AES operation mode from node A, get a private key based on said operation mode,
    # encrypt it and send it to node A.
    aes_operation_mode = os.read(a_to_km, 3).decode()
    aes_operation_mode_key = give_key(aes_operation_mode)
    encrypted_key = ecb_block_encryption(common_key, aes_operation_mode_key)
    os.write(km_to_a, encrypted_key)

    # print data in order to check that communication between the members is working correctly.
    print(f'Public key: {common_key}\n')
    print(f'AES operation mode: {aes_operation_mode}\n')
    print(f'Encrypted private key: {encrypted_key}\n')
    print(f'Private key: {aes_operation_mode_key}\n')

    # close all communication channels.
    os.close(a_to_km)
    os.close(km_to_a)
