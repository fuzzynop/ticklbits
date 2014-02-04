#! /usr/bin/python2.7

__author__ = 'fuzzynop'

import argparse
import actions
import binascii
import sys


#TODO write this function
def output(args,data):
    #do output based on what output type was selected
    pass

def get_hex_or_ascii(s):
#-------------------------------------------------------
# get_hex_or_ascii parses a provided string checking if
# the string starts with 'hex'. If it does then the
# following values are treated as a hex string.
# Otherwise it is just the ascii string entered
#-------------------------------------------------------
    if s[:3] == 'hex':
        try:
            value = binascii.a2b_hex(s[3:])
        except TypeError as e:
            print '*** Not a valid Hex String'
            print '*** The value was parsed as hex because the first 3 characters were \'hex\''
            print '*** Error Reason:', e.message
            sys.exit(1)
    else:
        value = s
    return value

def get_input(args):
#-------------------------------------------------------
# get_input will check the args provided to the program
# and do 1 of 3 things:
#   1. Read the data from a file if -f was used
#   2. Take a string if -s was used
#   3. Read from stdin if neither was provided.
#--------------------------------------------------------
    data = ''
    if args.file is not None:
        data = args.file.read()
    elif args.str is not None:
        data = get_hex_or_ascii(args.str)
    else:
        data = sys.stdin.read()
    return data

def launch(args):

    #--------------|
    #   -   xor   -|
    #--------------|
    if args.action == 'xor':
        key = get_hex_or_ascii(args.key)
        data = get_input(args)
        result = actions.xor_against(key, data)

        #TODO make this output different formats using output flags
        print repr(result)[1:-1]
        return result

    #--------------|
    #   -   b64   -|
    #--------------|
    elif args.action == 'b64':
        data = get_input(args)
        if args.encode is True:
            #do b64encode
            result = actions.b64_enc(data)
        elif args.decode is True:
            #do b64decode (try)
            result = actions.b64_dec(data)
        else:
            result = actions.b64_dec(data)
            #if none are true default action is going to be to decode
            #wrtiting seperately incase i want to change this later.
        print result
        return result

    #--------------|
    #   -   add   -|
    #--------------|
    elif args.action == 'add':
        data = get_input(args)
        result = actions.adjust_bytes(data, args.amount)
        print result

    #--------------|
    #   -   csr   -|
    #--------------|
    elif args.action == 'csr':
        data = get_input(args)
        result = actions.caeser_cipher(data, args.amount)
        print result

    #--------------|
    #   -   hex   -|
    #--------------|
    elif args.action == 'hex':
        data = get_input(args)
        print args
        if args.asciitohex is True:
            #take ascii and make it hex
            result = actions.hex_to_hexstring(data)
        elif args.hextoascii is True:
            #take hex and form ascii from it
            result = actions.hexstring_to_hex(data)
        else:
            result = actions.hex_to_hexstring(data)
        print repr(result)
        return result

    #--------------|
    #   -   mfb   -|
    #--------------|
    elif args.action == 'mfb':
        data = get_input(args)
        result = actions.most_frequent_byte(data)
        for i in range(0, 5):
            print repr(result[i][0]), ':', result[i][1]


def start_parser():
    #This function is responsible for parsing arguments
    parser = argparse.ArgumentParser()
    #----------------------------------
    # Input Group for possible ways
    # to input data to script
    #----------------------------------
    input_group = parser.add_mutually_exclusive_group()
    #TODO: if file specified use file, is string specified use string, if none specified read from STDIN want to do things like cat * | ticklbits.py xor "aaa"
    input_group.add_argument("-f", "--file", help="File as input", type=file)
    input_group.add_argument("-s", "--str", help="String as input", type=str)


    #---------------------------------
    # Output group for possible ways
    # to output the data
    #---------------------------------
    #output_group = parser.add_mutually_exclusive_group()

    #-----------------------------------
    # Sub Parsers for each action set
    #-----------------------------------
    subparsers = parser.add_subparsers(dest='action', help='test')

    #------------------|
    #   xor parser     |
    #------------------|
    pars_xor = subparsers.add_parser('xor', help='xor (XOR Operation) --help,-h')
    pars_xor.add_argument('key', help="Key is ascii, if you want hex prepend 'hex', ie. hexFF00FA11")
    pars_xor.add_argument('--offset', type=int, help="Offset to start XOR from")

    #------------------|
    #   b64 parser     |
    #------------------|
    pars_b64 = subparsers.add_parser('b64', help='b64 (Base 64 Encode or Decode) --help,-h')
    b64_group = pars_b64.add_mutually_exclusive_group()
    b64_group.add_argument("-e", "--encode", action='store_true', help="Base64 Encode, (Default)")
    b64_group.add_argument("-d", "--decode", action='store_true', help="Base64 Decode, must have Valid Base64 String")

    #------------------|
    #   add parser     |
    #------------------|
    pars_add = subparsers.add_parser('add', help='add (Add or Subtract from Each Byte) --help,-h')
    pars_add.add_argument('amount', type=int, help="Amount to change each byte by, can be negative")

    #-------------------|
    #(csr) caeser parser|
    #-------------------|
    pars_csr = subparsers.add_parser('csr', help='csr (Caeser Cipher) --help,-h')
    pars_csr.add_argument('amount', type=int, help='Amount to rotate alphabet, can be negative')
    pars_csr.add_argument('-k', '--key', type=str, help='Key to use in keyed Caeser Cipher, changes alphabet used')

    #-------------------|
    #     hex parser    |
    #-------------------|
    pars_hex = subparsers.add_parser('hex', help='hex (Ascii <-> Hex) --help,-h')
    pars_hex.add_argument('-a2h', '--asciitohex', action='store_true', help='Convert ascii to hex')
    pars_hex.add_argument('-h2a', '--hextoascii', action='store_true', help='Convert hex to ascii')


    #-------------------|
    #     mfb parser    |
    # most frequent byte|
    #-------------------|
    pars_mfb = subparsers.add_parser('mfb', help='mfb (Most Frequent Byte) --help,-h')

    return parser.parse_args()

args = start_parser()
launch(args)