from Crypto.Cipher import AES

initialization_vector = b'!salem?#890day;1'


def byte_xor(bytes_str1, bytes_str2):
    return bytes([byte1 ^ byte2 for byte1, byte2 in zip(bytes_str1, bytes_str2)])


def ecb_block_encryption(key, plain_message_block):
    if len(plain_message_block) != 16:
        raise Exception("Invalid block length: block should be 128 bits (16 bytes) long!")

    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plain_message_block)


def ecb_block_decryption(key, cipher_message_block):
    if len(cipher_message_block) != 16:
        raise Exception("Invalid block length: block should be 128 bits (16 bytes) long!")

    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(cipher_message_block)


def cfb_block_encryption(key, plain_message_block, init_vector=None):
    if len(plain_message_block) != 16:
        raise Exception("Invalid block length: block should be 128 bits (16 bytes) long!")
    if init_vector is None:
        init_vector = initialization_vector
    if len(init_vector) != 16:
        raise Exception("Invalid initialization vector (IV) length: IV should be 128 bits (16 bytes) long!")

    cipher = AES.new(key, AES.MODE_ECB)
    new_init_vector = byte_xor(cipher.encrypt(init_vector), plain_message_block)
    return new_init_vector, new_init_vector


def cfb_block_decryption(key, cipher_message_block, init_vector=None):
    if len(cipher_message_block) != 16:
        raise Exception("Invalid block length: block should be 128 bits (16 bytes) long!")
    if init_vector is None:
        init_vector = initialization_vector
    if len(init_vector) != 16:
        raise Exception("Invalid initialization vector (IV) length: IV should be 128 bits (16 bytes) long!")

    cipher = AES.new(key, AES.MODE_ECB)
    new_init_vector = cipher_message_block
    return new_init_vector, byte_xor(new_init_vector, cipher.encrypt(init_vector))


def ecb_encryption(key, plain_message):
    msg_length = len(plain_message)
    if len(plain_message) % 16 != 0:
        padding_length = (msg_length // 16 + 1) * 16 - msg_length
        plain_message += b'\0' * padding_length

    cipher_message = []
    for block_index in range(0, msg_length, 16):
        plain_message_block = plain_message[block_index: block_index + 16]
        cipher_message_block = ecb_block_encryption(key, plain_message_block)
        cipher_message.append(cipher_message_block)
    return cipher_message


def ecb_decryption(key, cipher_message):
    msg_length = len(cipher_message)
    if len(cipher_message) % 16 != 0:
        padding_length = (msg_length // 16 + 1) * 16 - msg_length
        cipher_message += b'\0' * padding_length

    plain_message = []
    for block_index in range(0, msg_length, 16):
        cipher_message_block = cipher_message[block_index: block_index + 16]
        plain_message_block = ecb_block_decryption(key, cipher_message_block)
        plain_message.append(plain_message_block)
    return plain_message


def cfb_encryption(key, plain_message, init_vector=None):
    msg_length = len(plain_message)
    if len(plain_message) % 16 != 0:
        padding_length = (msg_length // 16 + 1) * 16 - msg_length
        plain_message += b'\0' * padding_length

    cipher_message = []
    for block_index in range(0, msg_length, 16):
        plain_message_block = plain_message[block_index: block_index + 16]
        init_vector, cipher_message_block = cfb_block_encryption(key, plain_message_block, init_vector)
        cipher_message.append(cipher_message_block)
    return cipher_message


def cfb_decryption(key, cipher_message, init_vector=None):
    msg_length = len(cipher_message)
    if len(cipher_message) % 16 != 0:
        padding_length = (msg_length // 16 + 1) * 16 - msg_length
        cipher_message += b'\0' * padding_length

    plain_message = []
    for block_index in range(0, msg_length, 16):
        cipher_message_block = cipher_message[block_index: block_index + 16]
        init_vector, plain_message_block = cfb_block_decryption(key, cipher_message_block, init_vector)
        plain_message.append(plain_message_block)
    return plain_message
