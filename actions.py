import binascii
import base64

#--------------|
#   -   xor   -|
#--------------|
#xor against. data1 will be repeated against data2 as necessary so essentially data1 should be the xor key
def xor_against(data1, data2):
    data3 = ''
    i = 0
    #loop over all the data
    while i < len(data2):
        #append the character resulting from the key xor'd with the data
        #the key loops over itself using mod so to account for variable length keys
        data3 += chr(ord(data1[i % len(data1)]) ^ ord(data2[i]))
        i += 1
    return data3


#--------------|
#   -   hex   -|
#   hextoascii |
#--------------|
#tries to turn a hex string into hex values
#if it fails it just returns the same data (ie. do nothing)
def hexstring_to_hex(data):
    try:
        return binascii.a2b_hex(data)
    except:
        return data


#--------------|
#   -   hex   -|
#  asciitohex  |
#--------------|
def hex_to_hexstring(data):
    return binascii.b2a_hex(data)


#--------------|
#   -   b64   -|
#--------------|
#base64 encode
def b64_enc(data):
    return base64.b64encode(data)


#--------------|
#   -   b64   -|
#--------------|
#base64 decode
def b64_dec(data):
    try:
        return base64.b64decode(data)
    except:
        return data


#--------------|
#   -   add   -|
#--------------|
#adjust bytes
#this adds a value (can be negative) to each byte
#note: if a value exceeded 0xFF or goes below 0x00 it simply wraps around
#this is done to prevent accidental data loss and it just makes sense
def adjust_bytes(data, shift):
    data2 = ''
    #loop over all the data
    for i in range(0, len(data)):
        data2 += chr((ord(data[i]) + int(shift)) % 256)
    return data2


#--------------|
#   -   csr   -|
#--------------|
#ceaser cipher
#if the input is not text this function does nothing
def caeser_cipher(data, shift):
    alpha_lower = 'abcdefghijklmnopqrstuvwxyz'
    alpha_upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    data2 = ''
    for i in range(0, len(data)):
        if not (alpha_lower.find(data[i]) == -1):
            index = alpha_lower.find(data[i])
            index = (index + shift) % 26
            data2 += alpha_lower[index]
        elif not (alpha_upper.find(data[i]) == -1):
            index = alpha_upper.find(data[i])
            index = (index + shift) % 26
            data2 += alpha_upper[index]
        else:
            data2 += data[i]
    return data2


#--------------|
#   -   mfb   -|
#--------------|
#find most frequent byte
def most_frequent_byte(data):
    count = {}
    for byte in data:
        try:
            count[byte] = count[byte] + 1
        except KeyError:
            count[byte] = 1
        except:
            print "some other error things are bad.. its real bad .. i dont know but something bad happened"
    result = sorted(count.items(), key=lambda x: x[1], reverse=True)
    return result

